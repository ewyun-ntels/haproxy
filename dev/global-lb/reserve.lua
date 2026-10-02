-- UD-007/009/011 v2-r1-20261003. Redis/Valkey standalone RESP2 protocol.
-- KEYS: owners, liveness, counts, active requests. All keys are explicit.
-- ARGV: op, hex(instance), UUID, revision, request-id, high-water, timeout-ms,
--       tie-seed, max-instances, max-count-fields, max-requests, service,
--       candidate-count, candidates..., snapshot-count, request/endpoint...
-- request IDs/revisions use exact uint64 decimal comparison, never doubles.
local function reply(code, endpoint, count) return {code, endpoint or '', count or 0} end
local function uint(s, zero, max)
    return s and string.match(s, '^%d+$') and (#s == 1 or string.sub(s, 1, 1) ~= '0')
        and (zero or s ~= '0') and (#s < #max or (#s == #max and s <= max))
end
local function cmp(a, b)
    if #a ~= #b then return #a < #b and -1 or 1 end
    if a == b then return 0 end
    return a < b and -1 or 1
end
local function uuid(s)
    return s and #s == 36 and string.match(s,
        '^%x%x%x%x%x%x%x%x%-%x%x%x%x%-4%x%x%x%-[89ab]%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$')
        and s == string.lower(s)
end
local max64, maxint, maxexact = '18446744073709551615', '2147483647', '9007199254740991'
if #KEYS ~= 4 or #ARGV < 14 then return reply(-2) end
for i = 1, 4 do
    if #KEYS[i] == 0 then return reply(-2) end
    for j = 1, i-1 do if KEYS[i] == KEYS[j] then return reply(-2) end end
    local t = redis.call('TYPE', KEYS[i]).ok
    if t ~= 'none' and t ~= 'hash' then return reply(-3) end
end
local op, iid, gen, rev, rid, water = unpack(ARGV, 1, 6)
local valid_ops = {start=true, restore=true, reserve=true, release=true,
                   cancel=true, heartbeat=true, stop=true}
if not valid_ops[op] or #iid == 0 or #iid % 2 ~= 0 or not string.match(iid, '^[0-9a-f]+$')
    or not uuid(gen) or not uint(rev, false, max64) or not uint(rid, true, max64)
    or not uint(water, true, max64) then return reply(-2) end
for i = 7, 11 do if not uint(ARGV[i], false, maxint) then return reply(-2) end end
local timeout, seed, maxinst, maxfields, maxreq = unpack(ARGV, 7, 11)
timeout, seed = tonumber(timeout), tonumber(seed)
maxinst, maxfields, maxreq = tonumber(maxinst), tonumber(maxfields), tonumber(maxreq)
local service = ARGV[12]
if not uint(ARGV[13], true, maxint) then return reply(-2) end
local nc = tonumber(ARGV[13])
if nc > maxfields or 14 + nc > #ARGV then return reply(-5) end
local candidates, seen = {}, {}
for i = 1, nc do
    local e = ARGV[13+i]
    if #service == 0 or string.sub(e, 1, #service+1) ~= service .. '|'
        or #e <= #service+1 or seen[e] then return reply(-2) end
    seen[e], candidates[i] = true, e
end
local pos = 14 + nc
if not uint(ARGV[pos], true, maxint) then return reply(-2) end
local ns = tonumber(ARGV[pos])
if ns > maxreq then return reply(-5) end
if #ARGV ~= pos + 2*ns then return reply(-2) end
local control = op == 'start' or op == 'restore'
local request = op == 'reserve' or op == 'release' or op == 'cancel'
if (request and rid == '0') or (not request and rid ~= '0')
    or (not control and (ns ~= 0 or water ~= '0'))
    or (op == 'reserve' and nc == 0) or (op ~= 'reserve' and nc ~= 0) then return reply(-2) end
local snapshot, newcounts = {}, {}
for i = 1, ns do
    local id, e = ARGV[pos+2*i-1], ARGV[pos+2*i]
    if not uint(id, false, max64) or cmp(id, water) > 0 or snapshot[id]
        or not string.match(e, '^.+|.+$') then return reply(-2) end
    snapshot[id] = e
    newcounts[e] = (newcounts[e] or 0) + 1
end
if redis.call('HLEN', KEYS[1]) > maxinst or redis.call('HLEN', KEYS[2]) > maxinst
    or redis.call('HLEN', KEYS[3]) > maxfields or redis.call('HLEN', KEYS[4]) > maxreq then return reply(-5) end
local tm = redis.call('TIME')
local now = tonumber(tm[1])*1000 + math.floor(tonumber(tm[2])/1000)
local function metadata(id)
    local value = redis.call('HGET', KEYS[2], id)
    if not value then return nil end
    local r, hb, high, state = string.match(value, '^(%d+)|(%d+)|(%d+)|([ARD])$')
    if not uint(r, false, max64) or not uint(hb, true, maxexact)
        or not uint(high, true, max64) or tonumber(hb) > now then return nil end
    return {rev=r, hb=tonumber(hb), water=high, state=state}
end
local oldgen = redis.call('HGET', KEYS[1], iid)
local meta = metadata(iid)
if oldgen and (not uuid(oldgen) or not meta) then return reply(-3) end
if not oldgen and redis.call('HEXISTS', KEYS[2], iid) == 1
    and not (control and meta and meta.state == 'R') then return reply(-3) end
if oldgen and oldgen ~= gen and op ~= 'start' then return reply(-1) end
if not oldgen and not control then return reply(5) end
if oldgen == gen then
    if control then
        if meta.state == 'D' then return reply(-7) end
        local c = cmp(rev, meta.rev)
        if c < 0 then return reply(-4) end
        -- Confirming a repeated replacement MUST NOT erase later reservations.
        if c == 0 then
            if meta.state ~= 'A' then return reply(-7) end
            return reply(2)
        end
        if cmp(water, meta.water) < 0 then return reply(-4) end
    elseif rev ~= meta.rev then return reply(-4) end
end
if not control and meta.state ~= 'A' and op ~= 'stop' then return reply(-7) end
if (op == 'reserve' or op == 'heartbeat') and now-meta.hb > timeout then return reply(-6) end
local prefix = iid .. '|'
local function own_fields(key)
    local out = {}
    for _, field in ipairs(redis.call('HKEYS', key)) do
        if string.sub(field, 1, #prefix) == prefix then out[#out+1] = field end
    end
    return out
end
local owncounts, ownreq, endpoint, total = {}, {}, nil, 0
if control or op == 'stop' then
    owncounts, ownreq = own_fields(KEYS[3]), own_fields(KEYS[4])
    local nn = 0
    for _ in pairs(newcounts) do nn = nn+1 end
    if redis.call('HLEN', KEYS[3]) - #owncounts + nn > maxfields
        or redis.call('HLEN', KEYS[4]) - #ownreq + ns > maxreq
        or (not oldgen and redis.call('HLEN', KEYS[1]) >= maxinst) then return reply(-5) end
elseif op == 'reserve' then
    local owners = redis.call('HGETALL', KEYS[1])
    local active = {}
    for i = 1, #owners, 2 do
        local id, g = owners[i], owners[i+1]
        local m = metadata(id)
        if #id == 0 or #id % 2 ~= 0 or not string.match(id, '^[0-9a-f]+$')
            or not uuid(g) or not m then return reply(-3) end
        if m.state == 'A' and now-m.hb <= timeout then active[#active+1] = id end
    end
    local function aggregate(e)
        local sum = 0
        for _, id in ipairs(active) do
            local n = redis.call('HGET', KEYS[3], id .. '|' .. e)
            if n then
                if not uint(n, true, maxint) then return nil, -3 end
                sum = sum+tonumber(n)
                if sum >= tonumber(maxexact) then return nil, -5 end
            end
        end
        return sum
    end
    endpoint = redis.call('HGET', KEYS[4], prefix .. rid)
    if endpoint then
        if string.sub(endpoint, 1, #service+1) ~= service .. '|' then return reply(-3) end
        local n = redis.call('HGET', KEYS[3], prefix .. endpoint)
        if not uint(n, false, maxint) then return reply(-3) end
        local sum, error = aggregate(endpoint)
        if not sum then return reply(error) end
        return reply(2, endpoint, sum)
    end
    if cmp(rid, meta.water) <= 0 then return reply(0) end
    if redis.call('HLEN', KEYS[4]) >= maxreq then return reply(-5) end
    local best, ties = nil, {}
    for _, e in ipairs(candidates) do
        local sum, error = aggregate(e)
        if not sum then return reply(error) end
        if not best or sum < best then best, ties = sum, {e}
        elseif sum == best then ties[#ties+1] = e end
    end
    math.randomseed(seed)
    endpoint = ties[math.random(#ties)]
    total = best+1
    local n = redis.call('HGET', KEYS[3], prefix .. endpoint)
    if n and not uint(n, true, maxint) then return reply(-3) end
    if n and tonumber(n) >= tonumber(maxint) then return reply(-5) end
    if not n and redis.call('HLEN', KEYS[3]) >= maxfields then return reply(-5) end
elseif op == 'release' or op == 'cancel' then
    endpoint = redis.call('HGET', KEYS[4], prefix .. rid)
    if endpoint then
        local n = redis.call('HGET', KEYS[3], prefix .. endpoint)
        if not uint(n, false, maxint) then return reply(-3) end
    end
end
local function setmeta(state, r, hb, high)
    redis.call('HSET', KEYS[2], iid, r .. '|' .. string.format('%.0f', hb) .. '|' .. high .. '|' .. state)
end
-- Runtime write errors do not roll back Lua. Exclude this instance until a
-- fresh revision restore succeeds; error replies are never reserve success.
local ok, result = pcall(function()
    if control or op == 'stop' then
        local r = control and rev or meta.rev
        local high = control and water or meta.water
        setmeta('R', r, now, high)
        redis.call('HSET', KEYS[1], iid, gen)
        for _, f in ipairs(owncounts) do redis.call('HDEL', KEYS[3], f) end
        for _, f in ipairs(ownreq) do redis.call('HDEL', KEYS[4], f) end
        if control then
            for id, e in pairs(snapshot) do redis.call('HSET', KEYS[4], prefix .. id, e) end
            for e, n in pairs(newcounts) do redis.call('HSET', KEYS[3], prefix .. e, n) end
        end
        setmeta(op == 'stop' and 'D' or 'A', r, now, high)
        return reply(1)
    elseif op == 'heartbeat' then
        setmeta('A', meta.rev, now, meta.water)
        return reply(1)
    else
        local high = cmp(rid, meta.water) > 0 and rid or meta.water
        setmeta('R', meta.rev, meta.hb, high)
        if op == 'reserve' then
            redis.call('HINCRBY', KEYS[3], prefix .. endpoint, 1)
            redis.call('HSET', KEYS[4], prefix .. rid, endpoint)
        elseif endpoint then
            local n = redis.call('HINCRBY', KEYS[3], prefix .. endpoint, -1)
            if n == 0 then redis.call('HDEL', KEYS[3], prefix .. endpoint) end
            redis.call('HDEL', KEYS[4], prefix .. rid)
        end
        setmeta('A', meta.rev, meta.hb, high)
        if op == 'reserve' then return reply(1, endpoint, total) end
        if not endpoint then return reply(op == 'cancel' and 4 or 5) end
        return reply(op == 'cancel' and 4 or 3, endpoint)
    end
end)
if not ok then
    -- Best effort only: allocation/ACL failures may also prevent invalidation.
    -- The caller must fallback and reconnect/restore after ANY error.
    if redis.call('HGET', KEYS[1], iid) == gen then
        redis.pcall('HSET', KEYS[2], iid, rev .. '|' .. string.format('%.0f', now) .. '|' ..
            (control and water or meta.water) .. '|R')
    end
    return redis.error_reply('ERR global-lb reservation write failed; restore required')
end
return result

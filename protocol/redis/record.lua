local key = KEYS[1]
local fence_key = KEYS[2]
local op = ARGV[1]
local owner = ARGV[2]
local fence_arg = ARGV[3]
local lock_ttl_ms = tonumber(ARGV[4])
local record_ttl = tonumber(ARGV[5])
local max_bytes = tonumber(ARGV[6])
local body = ARGV[7]

local function now_ms()
  local t = redis.call('TIME')
  return tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
end

local function encode(status, record)
  return cjson.encode({ status = status, record = record })
end

local function read_rec()
  local raw = redis.call('GET', key)
  if not raw then
    return nil
  end
  local ok, rec = pcall(cjson.decode, raw)
  if not ok or type(rec) ~= 'table' then
    return false
  end
  return rec
end

local function write_keep(rec)
  redis.call('SET', key, cjson.encode(rec), 'KEEPTTL')
end

local function lock_is_expired(rec, now)
  local lock_at = tonumber(rec.lock_expires_at_ms)
  return rec.state == 'in_progress' and lock_at ~= nil and lock_at <= now
end

local function expire_lock(rec, now)
  if not lock_is_expired(rec, now) then
    return false
  end
  rec.state = 'blocked'
  rec.reason = 'lock_expired'
  rec.lock_expires_at_ms = cjson.null
  write_keep(rec)
  return true
end

local function same_owner(rec)
  return rec.owner == owner and tonumber(rec.fence) == tonumber(fence_arg)
end

local function decode_body()
  if body == nil or body == '' then
    return {}
  end
  local ok, payload = pcall(cjson.decode, body)
  if not ok or type(payload) ~= 'table' then
    return nil
  end
  return payload
end

local now = now_ms()
local rec = read_rec()
if rec == false then
  return encode('corrupt', cjson.null)
end

if op == 'claim' then
  if not rec then
    local payload = decode_body()
    if not payload then
      return encode('rejected', cjson.null)
    end
    local fence_n = redis.call('INCR', fence_key)
    redis.call('EXPIRE', fence_key, record_ttl)
    rec = {
      v = 1,
      state = 'in_progress',
      dispatched = false,
      scope_id = payload.scope_id,
      operation_id = payload.operation_id,
      owner = owner,
      fence = fence_n,
      lock_expires_at_ms = now + lock_ttl_ms,
      snapshot = cjson.null,
      result = cjson.null,
      reason = cjson.null,
    }
    redis.call('SET', key, cjson.encode(rec), 'EX', record_ttl)
    return encode('claimed', rec)
  end
  expire_lock(rec, now)
  if rec.state == 'in_progress' then
    return encode('in_progress', rec)
  end
  if rec.state == 'completed' then
    return encode('completed', rec)
  end
  return encode('blocked', rec)
end

if not rec then
  return encode('empty', cjson.null)
end

expire_lock(rec, now)

if op == 'read' then
  if rec.state == 'completed' then
    return encode('completed', rec)
  end
  if rec.state == 'blocked' then
    return encode('blocked', rec)
  end
  return encode('in_progress', rec)
end

if op == 'resolve' then
  if rec.state ~= 'blocked' then
    return encode('rejected', rec)
  end
  local payload = decode_body()
  if not payload then
    return encode('rejected', rec)
  end
  if payload.scope_id ~= rec.scope_id or type(payload.evidence) ~= 'string' or payload.evidence == '' then
    return encode('rejected', rec)
  end
  if payload.decision == 'release' then
    redis.call('DEL', key)
    return encode('released', cjson.null)
  end
  if payload.decision ~= 'complete' or type(payload.result_json) ~= 'string' then
    return encode('rejected', rec)
  end
  if #payload.result_json > max_bytes then
    return encode('rejected', rec)
  end
  local ok, result = pcall(cjson.decode, payload.result_json)
  if not ok or type(result) ~= 'table' then
    return encode('rejected', rec)
  end
  rec.state = 'completed'
  rec.reason = cjson.null
  -- Keep the canonical text. cjson turns an empty table into {}.
  rec.result = payload.result_json
  rec.evidence = payload.evidence
  write_keep(rec)
  return encode('completed', rec)
end

if not same_owner(rec) then
  return encode('stale_owner', rec)
end

if rec.state == 'blocked' then
  return encode('blocked', rec)
end

if rec.state ~= 'in_progress' then
  return encode('rejected', rec)
end

if op == 'mark_dispatched' then
  if rec.dispatched then
    return encode('rejected', rec)
  end
  rec.dispatched = true
  if body ~= '' then
    local payload = decode_body()
    if not payload then
      return encode('rejected', rec)
    end
    rec.snapshot = body
  end
  write_keep(rec)
  return encode('marked', rec)
end

if op == 'abort' then
  if rec.dispatched then
    return encode('rejected', rec)
  end
  redis.call('DEL', key)
  return encode('aborted', cjson.null)
end

if op == 'release_not_applied' then
  if not rec.dispatched then
    return encode('rejected', rec)
  end
  redis.call('DEL', key)
  return encode('released', cjson.null)
end

if op == 'block' then
  local payload = decode_body()
  if not payload or type(payload.reason) ~= 'string' then
    return encode('rejected', rec)
  end
  rec.state = 'blocked'
  rec.reason = payload.reason
  rec.lock_expires_at_ms = cjson.null
  rec.result = cjson.null
  write_keep(rec)
  return encode('blocked', rec)
end

if op == 'complete' then
  if not rec.dispatched then
    return encode('rejected', rec)
  end
  if #body > max_bytes then
    rec.state = 'blocked'
    rec.reason = 'oversized_result'
    rec.lock_expires_at_ms = cjson.null
    rec.result = cjson.null
    write_keep(rec)
    return encode('blocked', rec)
  end
  local payload = decode_body()
  if not payload then
    return encode('rejected', rec)
  end
  rec.state = 'completed'
  rec.reason = cjson.null
  rec.lock_expires_at_ms = cjson.null
  rec.result = body
  write_keep(rec)
  return encode('completed', rec)
end

return encode('rejected', rec)

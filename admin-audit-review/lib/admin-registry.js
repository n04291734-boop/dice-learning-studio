const auth = require('./admin-storage');
const prefix = 'dice-lab:registry:v1:';
const script = `
local op, id, legacy, actor, expires, request, browser, generation =
  ARGV[1], ARGV[2], ARGV[3], ARGV[4], tonumber(ARGV[5]), ARGV[6], ARGV[7], ARGV[8]
local owner = ARGV[9]
local browserPrefix = ARGV[10]
local now = tonumber(redis.call('TIME')[1])
if op == 'auditlist' then
  local ids = redis.call('ZRANGE', KEYS[2], expires, expires + 4)
  local rows = {}
  for _, member in ipairs(ids) do
    local raw = redis.call('HGET', KEYS[1], member)
    if raw then
      table.insert(rows, {member, raw, redis.call('EXISTS', browserPrefix .. member)})
    end
  end
  return {now, rows, redis.call('ZCARD', KEYS[2])}
end
if op == 'ownerlookup' or op == 'ownerrevoke' then
  if not owner or not string.match(owner, '^%d+$') or #owner < 16 or #owner > 20 then return {'invalid'} end
  local count = redis.call('SCARD', KEYS[6])
  if count > 50 then return {'limit'} end
  local members = redis.call('SMEMBERS', KEYS[6])
  table.sort(members)
  local rows = {}
  local changed = 0
  for _, member in ipairs(members) do
    local raw = redis.call('HGET', KEYS[1], member)
    local rec = raw and cjson.decode(raw) or nil
    if rec and rec.adminOwner == owner then
      local bound = redis.call('EXISTS', browserPrefix .. member)
      if op == 'ownerlookup' then
        table.insert(rows, {member, raw, bound})
      elseif not rec.revoked then
        if bound == 1 and not rec.redeemedObservedAt then rec.redeemedObservedAt = now end
        rec.revoked = true
        redis.call('HSET', KEYS[1], member, cjson.encode(rec))
        redis.call('DEL', browserPrefix .. member)
        redis.call('LPUSH', KEYS[3], cjson.encode({action=op,keyRef=string.sub(member,1,12),actor=actor,at=now,request=request}))
        changed = changed + 1
      end
    end
  end
  if op == 'ownerlookup' then return {'ok',now,rows} end
  redis.call('LTRIM', KEYS[3], 0, 999)
  return {'ok',changed,#members}
end
local raw = redis.call('HGET', KEYS[1], id)
local record = raw and cjson.decode(raw) or nil
local function save(event)
  redis.call('HSET', KEYS[1], id, cjson.encode(record))
  redis.call('ZADD', KEYS[2], 0, id)
  redis.call('LPUSH', KEYS[3], cjson.encode({action=event, keyRef=string.sub(id,1,12), actor=actor, at=now, request=request}))
  redis.call('LTRIM', KEYS[3], 0, 999)
end
if not record then return {'missing'} end
if op == 'linkowner' then
  if not owner or not string.match(owner, '^%d+$') or #owner < 16 or #owner > 20 then return {'invalid'} end
  if record.adminOwner and record.adminOwner ~= owner then return {'conflict'} end
  if redis.call('SCARD', KEYS[6]) >= 50 and redis.call('SISMEMBER', KEYS[6], id) == 0 then return {'limit'} end
  record.adminOwner = owner
  redis.call('SADD', KEYS[6], id)
  save(op)
  return {'ok'}
end
if record.revoked then
  if op == 'revoke' then return {'ok'} end
  return {'revoked'}
end
if op == 'revoke' then
  if redis.call('EXISTS', KEYS[4]) == 1 and not record.redeemedObservedAt then record.redeemedObservedAt = now end
  record.revoked = true
  redis.call('DEL', KEYS[4])
  save(op)
  return {'ok'}
end
return {'unknown'}
`;
const allowed = new Set(['auditlist','linkowner','ownerlookup','ownerrevoke','revoke']);
function run(op, id, opts = {}) {
  if (!allowed.has(op)) throw Error('Unsupported administrator operation');
  return auth.redis(['EVAL', script, '6', prefix + 'records', prefix + 'index', prefix + 'audit',
    auth.storageKey(id), prefix + 'request:' + (opts.request || 'none'), prefix + 'owner:' + (opts.owner || 'none'), op, id, '0', opts.actor || '', String(opts.expires ?? 0),
    opts.request || '', '', '', opts.owner || '', auth.storageKey('')]);
}
module.exports = {run};

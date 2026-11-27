const isHex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
async function redis(command) {
  const direct = process.env.UPSTASH_REDIS_REST_URL;
  const endpoint = new URL(direct || process.env.KV_REST_API_URL || '');
  const token = direct ? process.env.UPSTASH_REDIS_REST_TOKEN : process.env.KV_REST_API_TOKEN;
  if (endpoint.protocol !== 'https:' || !token) throw new Error('Storage unavailable');
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify(command),
    redirect: 'error',
    signal: AbortSignal.timeout(1900)
  });
  if (!response.ok) throw new Error('Storage unavailable');
  const reply = await response.json();
  if (reply.error || !Object.hasOwn(reply, 'result')) throw new Error('Storage unavailable');
  return reply.result;
}
const storageKey = id => 'dice-lab:browser:v1:' + id;
module.exports = {isHex, redis, storageKey};

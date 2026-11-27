const crypto = require('node:crypto');
const auth = require('../lib/admin-storage');
const registry = require('../lib/admin-registry');
const commands = require('../lib/admin-commands');
const spki = Buffer.from('302a300506032b6570032100', 'hex');
const privateReply = value => ({type: 4, data: {...(typeof value === 'string' ? {content: value} : {embeds: [value]}), flags: 64, allowed_mentions: {parse: []}}});
const status = (record, now) => record.revoked ? 'Revoked' : record.expires && record.expires <= now ? 'Expired' : 'Active';
async function execute(interaction) {
  const {name} = interaction.data;
  const args = Object.fromEntries((interaction.data.options || []).map(({name, value}) => [name, value]));
  const opts = {actor: interaction.member.user.id, request: interaction.id};
  const id = args.id;
  const account = args.user;
  const validAccount = typeof account === 'string' && /^\d{16,20}$/.test(account);
  const page = args.page ?? 1;
  const validPage = Number.isSafeInteger(page) && page >= 1 && page <= 100000;
  function auditEmbed(title, total, rows, now) {
    return {
      title: '🔑 ' + title,
      color: 0xB56CFF,
      description: 'Private administrator audit · page ' + page + ' of ' + Math.ceil(total / 5),
      fields: rows.map(([keyId, raw, bound]) => {
        const record = JSON.parse(raw);
        const state = status(record, now);
        const registered = Number(bound) === 1;
        const linked = typeof record.adminOwner === 'string' && /^\d{16,20}$/.test(record.adminOwner);
        const redemption = registered ? 'Browser registered'
          : record.redeemedObservedAt ? 'Previously registered' : 'No recorded redemption';
        const headline = state === 'Revoked' ? '🔴 Revoked'
          : state === 'Expired' ? '🟡 Expired'
          : registered ? '🟢 Browser registered' : '⚪ ' + redemption;
        const lines = [
          headline,
          'Account association: ' + (linked ? 'Admin linked' : 'Unknown'),
        ];
        if (state !== 'Active') lines.push(redemption);
        lines.push('Key ID: ' + keyId);

        return {
          name: '\u200b',
          value: '**' + (linked ? '<@' + record.adminOwner + '>' : 'Unknown account') + '**\n' + lines.join('\n'),
        };
      }),
      footer: {text: 'Browser registration alone cannot verify Discord identity. Use the key ID for revocation.'},
    };
  }
  if (name === 'redeemed') {
    if (!validPage) return 'Enter a valid page.';
    const [now, rows, count] = await registry.run('auditlist','',{expires:(page-1)*5});
    if (!rows.length) return 'No entries on this page. Unindexed legacy keys are not listed.';
    return auditEmbed('Redemption audit',count,rows.slice(0,5),now);
  }
  if (name === 'linkowner') {
    if (!validAccount || !auth.isHex(id) || args.confirm !== true) return 'Provide an existing key ID, confirmed Discord account and confirmation.';
    const [result] = await registry.run('linkowner',id,{...opts,owner:account});
    return {ok:'Owner association recorded for admin revocation only. This does not verify who redeemed the key.',missing:'Key ID not found.',conflict:'Key is already linked to another account; no change made.',limit:'Account association limit reached; no change made.'}[result] || 'No change made.';
  }
  if (name === 'lookup' || name === 'blacklist') {
    if (!validAccount) return 'Choose a valid Discord account.';
    if (name === 'blacklist') {
      if (args.confirm !== true) return 'Set confirm to true to permanently revoke linked existing keys.';
      const [result,count,total] = await registry.run('ownerrevoke','',{...opts,owner:account});
      if (result !== 'ok') return 'No change made; review associated keys first.';
      return 'Revoked ' + count + ' existing keys for <@' + account + '>. Linked records: ' + total + '. Unlinked keys are unaffected. This is not a future account ban.';
    }
    if (!validPage) return 'Enter a valid page.';
    const [result,now,rows] = await registry.run('ownerlookup','',{...opts,owner:account});
    if (result !== 'ok') return 'Lookup unavailable; review key IDs individually.';
    const shown=rows.slice((page-1)*5,page*5);
    if (!shown.length) return 'No linked keys on this page. Unknown owners cannot be inferred.';
    return auditEmbed('Manually linked keys',rows.length,shown,now);
  }
  if (name === 'revoke') {
    if (!auth.isHex(id) || args.confirm !== true) return 'Provide an existing key ID and confirm permanent revocation.';
    const [result] = await registry.run('revoke',id,opts);
    return result === 'ok' ? 'Existing key revoked. Its registered browser session was removed.' : 'No change made: key not found.';
  }
  return 'Unsupported administrator command.';
}
async function rawBody(req) {
  const chunks=[]; let bytes=0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if(bytes>65536) throw Error('Body exceeds limit');
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}
module.exports = async (req,res) => {
  res.setHeader('Cache-Control','no-store');
  if(req.method !== 'POST') return res.status(405).end();
  const publicKey=process.env.DISCORD_PUBLIC_KEY, sig=req.headers['x-signature-ed25519'], ts=req.headers['x-signature-timestamp'];
  if(!auth.isHex(publicKey) || !/^[0-9a-f]{128}$/i.test(sig||'') || !/^\d{10}$/.test(ts||'') || Math.abs(Date.now()/1000-Number(ts))>300) return res.status(401).end();
  let interaction;
  try {
    const raw=await rawBody(req);
    const key=crypto.createPublicKey({key:Buffer.concat([spki,Buffer.from(publicKey,'hex')]),format:'der',type:'spki'});
    if(!crypto.verify(null,Buffer.concat([Buffer.from(ts),raw]),key,Buffer.from(sig,'hex'))) return res.status(401).end();
    interaction=JSON.parse(raw);
  } catch {return res.status(401).end();}
  if(interaction.type===1) return res.status(200).json({type:1});
  if(interaction.type!==2 || !commands.some(c=>c.name===interaction.data?.name)) return res.status(400).end();
  const member=interaction.member;
  if(!interaction.guild_id || interaction.guild_id!==process.env.DISCORD_GUILD_ID || !/^\d{16,20}$/.test(interaction.id||'') ||
    !/^\d{16,20}$/.test(member?.user?.id||'') || !/^\d+$/.test(member?.permissions||'') || !(BigInt(member.permissions)&8n)) {
      return res.status(200).json(privateReply('This command is available only to administrators in the configured server.'));
  }
  try {return res.status(200).json(privateReply(await execute(interaction)));}
  catch {return res.status(200).json(privateReply('Key storage is temporarily unavailable. Check the key status before retrying a change.'));}
};
module.exports.config={api:{bodyParser:false}};

const option = (name, description, type = 3, required = false) => ({name, description, type, required});
const ref = option('id', 'Existing key ID from the audit', 3, true);
const command = (name, description, options = []) =>
  ({name, description, options, default_member_permissions: '8', type: 1});
module.exports = [
  command('revoke', 'Permanently revoke an existing key', [ref, option('confirm', 'Confirm permanent revocation', 5, true)]),
  command('redeemed', 'Audit key redemption and browser status privately', [option('page', 'Registry page number', 4)]),
  command('linkowner', 'Record an independently confirmed owner of an existing key', [ref, option('user', 'Confirmed Discord account', 6, true), option('confirm', 'Confirm you verified this association', 5, true)]),
  command('lookup', 'Find existing keys manually linked to a Discord account', [option('user', 'Discord account', 6, true), option('page', 'Page number', 4)]),
  command('blacklist', 'Revoke all existing keys linked to a Discord account', [option('user', 'Discord account', 6, true), option('confirm', 'Confirm permanent revocation', 5, true)]),
];

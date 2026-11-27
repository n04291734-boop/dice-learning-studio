# Dice Lab administrator-only audit review

This directory stages the restricted administrator module for review. It is intentionally outside the deployed root api directory. Do not merge it as a replacement for the original bot or change the existing Discord interaction endpoint.

Commands: /redeemed (indexed key audit), /lookup user (manually linked keys), /linkowner id user confirm:true (record an independently confirmed account association), /blacklist user confirm:true (revoke existing linked keys), and /revoke id confirm:true (revoke an existing indexed key). No issuance, extension, activation, browser reset, or login code is included. All commands require a verified signed request, the configured guild and Administrator permissions; replies are private.

The existing registry records browser registration, not verified Discord identity. Account associations are administrative assertions. Unknown owners remain unknown. Unindexed legacy keys are excluded. Revocation does not affect unlinked keys or impose a future account ban.

The original bot and registry source are missing from the connected main branch. The staged module must be tested in an isolated environment before any live integration. No credentials are included. No production settings are changed. The earlier local package was syntax-checked and tested with mocked interactions; this staged copy has not been tested against live Redis or Discord.

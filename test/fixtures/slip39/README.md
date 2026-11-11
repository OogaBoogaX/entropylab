# SLIP-39 test vectors

`vectors.json` is an unchanged copy of the official SLIP-0039 test vectors:
the file the specification's Test vectors section links, from
python-shamir-mnemonic v0.3.0 (commit
`08bbb74bdcb58c918981836cb3ccf401e57ecfb4`, MIT), unchanged in that
repository since the tag. SHA-256
`13ebecebdd869dd2bc2cdf69e7ce3a158cf106cac76c39d17682b1c6cdabbdc4`, pinned by
`test/slip39.test.mjs`.

Each entry is `[description, mnemonics, master secret hex, BIP32 master
xprv]`; an empty master secret means the set must be refused. Every valid set
uses the passphrase the specification names in that section.

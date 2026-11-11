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

`reference-sets.json` holds 19 share sets split by the same reference
implementation, v0.3.0, with its random source replaced by a recorded
stream. Regenerate it with `python3 -I scripts/slip39-reference.py
<python-shamir-mnemonic checkout>`; the script refuses any reference file
whose SHA-256 differs from v0.3.0's and needs only Python's standard library.
Each set lists its master secret, passphrase, encrypted master secret,
identifier, the shares of every group, and every random value the split
drew: the identifier, the shares drawn at random at x = 0..T-3 and the
random part R of each digest share, at the group level and per group. Eight
sets cover combining (128 to 256 bits, one and two levels, extendable or
not, exponents 0 to 2, with and without a passphrase); the rest model what
the randomness test must catch: independent runs, a generator restarted
from the same state (read the same way and shifted), one buffer returned on
every draw, single draws replaced by zero, one repeated byte or a counter,
and a group-level R reused. The master secrets and streams come from
SHA-256 of fixed labels; none is a real wallet. `test/slip39-reference.test.mjs`
compares `src/js/slip39.js` with these draws.

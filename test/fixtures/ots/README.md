# OpenTimestamps verifier fixtures

- `opentimestamps-client/`: the example proofs and their original files from
  [opentimestamps-client](https://github.com/opentimestamps/opentimestamps-client/tree/cd71c7609421bed2a07b9642a3c02a58c9fd2cdf/examples)
  at commit `cd71c76`, unchanged (including the project's own README files).
  The client is LGPL-3.0; these are machine-generated proof files and short
  text samples, kept here as test data only.
- `entropylab-v1.0.0/`: this project's own v1.0.0 release proof and checksum
  manifest. It carries three completed Bitcoin attestations (blocks 970791,
  970794 and 970801) and four pending calendar attestations.
- `headers.json`: the real 80-byte block header of every attested height,
  fetched from blockstream.info on 2026-10-27. Each one was checked to
  double-SHA256-hash to its block hash.
- `expected.json`: the expected outcome of each case, recorded with an
  independent minimal walker, not with the code under test.

Every original file hashes to the digest its proof carries. Both fixture folders
are marked binary in `.gitattributes`, so git never rewrites a byte.

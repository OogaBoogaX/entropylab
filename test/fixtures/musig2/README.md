# MuSig2 test vectors

Taken from bitcoin/bips at commit
`ada341963ab3916e74c98e6de4ba48babc024a75` (2026-11-02):

- `bip327-key_sort_vectors.json`, `bip327-key_agg_vectors.json`,
  `bip327-tweak_vectors.json`: unchanged copies of `bip-0327/vectors/`
  (BIP-327, MuSig2).
- `bip373-vectors.json`: all 24 PSBTs in the Test Vectors section of
  `bip-0373.mediawiki` (12 spends, 2 receives, 10 invalid), each base64 string
  copied byte for byte into our own JSON layout, with the aggregate key and
  the participants' public keys. The published private keys are left out:
  public verification does not need them. At this commit the BIP's
  "PSBT with an x-only output participant pubkey" vector repeats the bytes of
  "PSBT with x-only aggregate pubkey in output participant pubkeys keydata";
  it is kept as published, and the tests account for it.

Do not edit these files; refresh them from upstream instead.

# MuSig2 test vectors

Copied byte for byte from bitcoin/bips at commit
`ada341963ab3916e74c98e6de4ba48babc024a75` (2026-11-02):

- `bip327-key_sort_vectors.json`, `bip327-key_agg_vectors.json`,
  `bip327-tweak_vectors.json`: `bip-0327/vectors/` (BIP-327, MuSig2).
- `bip373-vectors.json`: the PSBTs in the Test Vectors section of
  `bip-0373.mediawiki` (BIP-373, MuSig2 PSBT fields), with the aggregate key
  and the participants' public keys. The published private keys are left out:
  public verification does not need them.

Do not edit these files; refresh them from upstream instead.

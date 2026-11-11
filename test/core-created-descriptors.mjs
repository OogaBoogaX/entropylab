// The eight walletdescriptor records of a wallet Bitcoin Core created itself:
// `bitcoin-wallet -regtest -wallet=<name> create`, Bitcoin Core v32.1.0, 2026-11-10.
// Public data only: each record's descriptor text as stored, and the 32-byte
// record id (Core's DescriptorID) from the record key. Read from the file's
// SQLite `main` table; the key records were never read and the wallet was a
// throwaway that was deleted.
//
// What they pin: Core stores its own descriptors with the hardened steps AFTER
// the key and no [origin], and the id is the SHA-256 of the compat form, in
// which every one of those steps is written with an apostrophe.
export const CORE_CREATED_BY = "Bitcoin Core v32.1.0 (bitcoin-wallet create, regtest)";
export const CORE_CREATED_DESCRIPTORS = [
  { descriptor: "pkh(tpubD6NzVbkrYhZ4XRXcqdzHxWiWi9SqzQ16EsXxdYb5Bn3AtFu8iT7269RzdcSeabw3gN31TmLUNa16jxJ1UBiQ1gRs9HMtNEKB6mY7AgHGBtk/44h/1h/0h/0/*)#9unk67zn",
    id: "c6e13e090d993c5b873cabe783e467851a7dd6b34f51667afa8db399878accf0" },
  { descriptor: "pkh(tpubD6NzVbkrYhZ4XRXcqdzHxWiWi9SqzQ16EsXxdYb5Bn3AtFu8iT7269RzdcSeabw3gN31TmLUNa16jxJ1UBiQ1gRs9HMtNEKB6mY7AgHGBtk/44h/1h/0h/1/*)#5gkh8tjt",
    id: "3492baf0c8f3ccd8b4d09b42a9a9e61e8015f285857375c6ab785b1a5d2e8fb6" },
  { descriptor: "sh(wpkh(tpubD6NzVbkrYhZ4XRXcqdzHxWiWi9SqzQ16EsXxdYb5Bn3AtFu8iT7269RzdcSeabw3gN31TmLUNa16jxJ1UBiQ1gRs9HMtNEKB6mY7AgHGBtk/49h/1h/0h/0/*))#dnyr22l5",
    id: "be02cb775f7f34d30b01ef21e5d80510a2691fbf6c368c88057eb655ad948ec3" },
  { descriptor: "sh(wpkh(tpubD6NzVbkrYhZ4XRXcqdzHxWiWi9SqzQ16EsXxdYb5Bn3AtFu8iT7269RzdcSeabw3gN31TmLUNa16jxJ1UBiQ1gRs9HMtNEKB6mY7AgHGBtk/49h/1h/0h/1/*))#tsvx385q",
    id: "7643574190c580324dd686f92b12f17fa2a9f319070c799953b7c2568141eafb" },
  { descriptor: "tr(tpubD6NzVbkrYhZ4XRXcqdzHxWiWi9SqzQ16EsXxdYb5Bn3AtFu8iT7269RzdcSeabw3gN31TmLUNa16jxJ1UBiQ1gRs9HMtNEKB6mY7AgHGBtk/86h/1h/0h/0/*)#q3mgwvun",
    id: "67ab01b234cf6a1f6ba0b9cf98b1442e949d840c32d51d03cd84db1b702c3c1d" },
  { descriptor: "tr(tpubD6NzVbkrYhZ4XRXcqdzHxWiWi9SqzQ16EsXxdYb5Bn3AtFu8iT7269RzdcSeabw3gN31TmLUNa16jxJ1UBiQ1gRs9HMtNEKB6mY7AgHGBtk/86h/1h/0h/1/*)#397fnevt",
    id: "fbbd73cdb485d73d840c4d51ff74c78cbf1c256c7becb6ef600c771becaa667b" },
  { descriptor: "wpkh(tpubD6NzVbkrYhZ4XRXcqdzHxWiWi9SqzQ16EsXxdYb5Bn3AtFu8iT7269RzdcSeabw3gN31TmLUNa16jxJ1UBiQ1gRs9HMtNEKB6mY7AgHGBtk/84h/1h/0h/0/*)#sw6uh0u0",
    id: "aee5e96698215079b7f9365fdfcf01aa63bd5f4ed923b53180d24f7e856d982c" },
  { descriptor: "wpkh(tpubD6NzVbkrYhZ4XRXcqdzHxWiWi9SqzQ16EsXxdYb5Bn3AtFu8iT7269RzdcSeabw3gN31TmLUNa16jxJ1UBiQ1gRs9HMtNEKB6mY7AgHGBtk/84h/1h/0h/1/*)#p6la26vh",
    id: "998e4918ab5a34896501a1702793ab6b1382864453b2e741d7803125ebecb558" },
];

// Five more records from the same Bitcoin Core v32.1.0, on a regtest node with
// no network connections: descriptors given to `importdescriptors` in a blank
// wallet. The private keys were throwaways; only the stored public text and the
// record id are kept. They cover shapes a created wallet does not have: a
// hardened wildcard, an origin together with hardened steps after the key, a
// multisig with two keys, and a descriptor already written with apostrophes.
// (Core refuses an uppercase H marker: "Key path value '44H' is not a valid
// uint32", so no record can carry one.)
export const CORE_IMPORTED_DESCRIPTORS = [
  { descriptor: "tr(tpubD6NzVbkrYhZ4Y2Ssyik4tEUuzfDrqQa9sTeuteKq3Q7v8q4tSXfw6u2CrEvFYhf2f42wRCSfk8TXFA1wUsNCsQE96P7AXnavmPQUrhKctjv/86h/1h/9h/0/*)#yvaat0x2",
    id: "8042c99cca6d83f531cbd4eca6a05be5b62573e0b55b7a8f753b0d44bc7e0224" },
  { descriptor: "wpkh([deadbeef/84h/1h/0h]tpubD6NzVbkrYhZ4Y2Ssyik4tEUuzfDrqQa9sTeuteKq3Q7v8q4tSXfw6u2CrEvFYhf2f42wRCSfk8TXFA1wUsNCsQE96P7AXnavmPQUrhKctjv/7h/0/*)#j6ke5lkj",
    id: "1094fa950f6939a6ca08f03b7fcfb4ed07a75bceaddea8804b857a359b95c7d8" },
  { descriptor: "wpkh(tpubD6NzVbkrYhZ4Y2Ssyik4tEUuzfDrqQa9sTeuteKq3Q7v8q4tSXfw6u2CrEvFYhf2f42wRCSfk8TXFA1wUsNCsQE96P7AXnavmPQUrhKctjv/84'/1'/6'/0/*)#f7q40gm4",
    id: "f1dd39cc2712ee04dc56d7ae70eda29d36190ad58d1dababd1a40708fe061808" },
  { descriptor: "wpkh(tpubD6NzVbkrYhZ4Y2Ssyik4tEUuzfDrqQa9sTeuteKq3Q7v8q4tSXfw6u2CrEvFYhf2f42wRCSfk8TXFA1wUsNCsQE96P7AXnavmPQUrhKctjv/84h/1h/5h/0/*h)#kjjm3tp3",
    id: "53fda2c5334ba37cd299d2f5e0b371030f904f448dce3e15f70fff207ea4c2bb" },
  { descriptor: "wsh(sortedmulti(1,tpubD6NzVbkrYhZ4Y2Ssyik4tEUuzfDrqQa9sTeuteKq3Q7v8q4tSXfw6u2CrEvFYhf2f42wRCSfk8TXFA1wUsNCsQE96P7AXnavmPQUrhKctjv/48h/1h/0h/2h/0/*,tpubD6NzVbkrYhZ4Y2Ssyik4tEUuzfDrqQa9sTeuteKq3Q7v8q4tSXfw6u2CrEvFYhf2f42wRCSfk8TXFA1wUsNCsQE96P7AXnavmPQUrhKctjv/48h/1h/1h/2h/0/*))#6q8y0fq4",
    id: "37ee7f2519d4f39f97753f6da839f7ab1c172f69abfea63da89d6f78f1ee5010" },
];

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

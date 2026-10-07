# Messaging

This document holds the words EntropyLab uses to describe itself in public:
the website, release announcements, social posts, directory listings, talks,
and anything else written for people who have not opened the app yet. It is a
shared starting point, so that anyone speaking for the project can reuse
agreed wording instead of writing it from scratch, and so that what we say
stays consistent from one channel to the next.

## Contents

- [Why it lives in the repository](#why-it-lives-in-the-repository)
- [Ground rules](#ground-rules)
- [How to contribute](#how-to-contribute)
- [What is EntropyLab?](#what-is-entropylab)
  - [In one line](#in-one-line)
  - [In a paragraph](#in-a-paragraph)
  - [At length](#at-length)
  - [What it is not](#what-it-is-not)
- [Who is EntropyLab for?](#who-is-entropylab-for)
  - [Who it is not for](#who-it-is-not-for)
- [User stories](#user-stories)

## Why it lives in the repository

EntropyLab is a tool for handling Bitcoin keys, and the way we describe it is
part of its security. A sentence such as "works fully offline" or "the build
is reproducible" is a claim people rely on when deciding whether to trust the
software. Keeping the copy here means every change goes through the same
review as the code, by people who can tell whether a claim is still true, and
the history records who changed what and why.

## Ground rules

- **Accurate before persuasive.** Say only what the software does today. If
  a claim needs a qualifier to be true, the qualifier goes in the copy.
- **Every claim points to its proof.** A statement about security,
  privacy, or verification links to where it is shown: the code, a test,
  [SECURITY.md](../SECURITY.md), or [Reproductions.md](Reproductions.md).
- **The project's status comes first.** While the README restricts use to
  test networks, public copy says so as plainly as the README does, and
  never implies otherwise.
- **The app and the README win.** If this document disagrees with them, it
  is this document that is out of date.

## How to contribute

Propose new or changed wording through a pull request, like any other
change. Say in the description where the copy will be used, and link the
proof for any new claim. Wording inside the app is not kept here: it lives
in `src/` and is translated by the project's translation workflow. This
document is written in English and is not machine-translated.

## What is EntropyLab?

### In one line

EntropyLab is a Bitcoin key and wallet calculator in a downloadable HTML
file, intended to be run on an offline air-gapped computer.

### In a paragraph

EntropyLab turns entropy and key material you bring, such as dice rolls,
coin flips, a seed phrase, or an extended key, into the wallet details you
need to back up and verify: seed words, keys, fingerprints, descriptors, and
addresses. It is one self-contained HTML file. You download it, check it,
and open it in a browser on a computer that is not connected to anything.
It makes no network requests, and you do not need to install anything.

### At length

Every hardware and software wallet on the market today requires you to
trust a process you cannot see. Either the wallet creates your private key,
and you trust that sufficient entropy was used, or you supply your own
entropy, and you trust that it was properly used. EntropyLab removes that
blind spot. Its tools let you verify any step from entropy to addresses. You
can create new key material directly using your own dice rolls, coin flips,
or playing cards, on an offline, air-gapped computer. Everything follows the
open standards wallets are built on (BIP39, BIP32, the BIP44, 49, 84, and 86
derivation schemes, and output descriptors), so every result can be checked
against any other wallet or signing device.

In addition to key verification and generation, EntropyLab allows you to
build watch-only multisig wallets, inspect and edit partially signed
transactions (PSBTs) without signing them, and derive BIP-85 child keys,
Silent Payment addresses, and vanity addresses.

The whole tool is one HTML file with no server behind it. Every release can be
rebuilt from source to the same bytes, and independent contributors have
done so and signed the result.

### What it is not

- **Not a source of randomness.** EntropyLab never creates secret entropy
  for you. It works only with what you give it.
- **Not a wallet or a signer.** It does not hold funds, sign transactions,
  or broadcast them. Use a separately verified wallet or signing device for
  that.
- **Not something to use online with real keys.** Wallet secrets belong on
  an offline computer, never on a connected one.

## Who is EntropyLab for?

- **Self-custody users who want to verify, not trust.** People who hold
  their own keys and want to confirm that a seed phrase, a backup, or a
  wallet's addresses are exactly what they should be, using a tool that is
  independent of the wallet that produced them.
- **People who create their own keys.** Anyone who would rather roll dice,
  flip coins, or shuffle cards than rely on a device's randomness, and wants
  to turn that entropy into a standard seed phrase on an offline computer.
- **Multisig coordinators.** People setting up or auditing a multisig
  wallet who need to assemble co-signer keys into a watch-only wallet and
  check its descriptor and addresses before any funds arrive.
- **Recovery and inheritance.** Anyone reconstructing a wallet from a
  backup, an old key, or a set of co-signer details, who needs to see the
  derivation paths and addresses spelled out before moving funds.
- **Bitcoin users who want to learn how it works.** People who want to
  understand the technical side of wallet creation and self-custody: how
  entropy becomes a seed phrase, how keys and addresses are derived, and
  what a descriptor or a multisig wallet is made of.
- **Developers, testers, and educators.** People who work with Bitcoin
  keys and need a transparent reference for test vectors, test networks,
  workshops, or teaching how a seed becomes an address.

### Who it is not for

EntropyLab is not for total beginners. It assumes you are familiar with
seed phrases, derivation paths, and the habits of keeping secrets offline.
Someone looking for a simple way to store and spend bitcoin is better served
by a well-reviewed wallet or signing device, and can come back to EntropyLab
to check that wallet's work.

## User stories

Short scenarios showing who uses EntropyLab and why. Each one names a
person, the problem they have, what they do with EntropyLab, and what they
gain. The names follow the cast Bitcoin writing traditionally uses for
hypothetical people. Every story assumes EntropyLab runs on an offline,
air-gapped computer.

- **Bob** owns a hardware wallet but doesn't feel comfortable trusting the
  seed phrase it gave him. He rolls dice, turns the rolls into a new seed
  phrase with EntropyLab on an offline computer, and loads it onto his
  hardware wallet. Now he only needs to trust the hardware wallet for signing
  transactions.
- **Alice** has used her hardware wallet for years and wants to be sure her
  paper backup really restores it. She uses EntropyLab on an offline computer
  to enter the seed phrase and confirm that the receive addresses match the
  ones her wallet shows, without ever restoring it on a second device.
- **Carol** is setting up a 2-of-3 multisig with two family members. She
  collects each co-signer's extended public key, uses EntropyLab on an offline
  computer to build the watch-only wallet, and checks the descriptor and first
  addresses on every signing device before anyone sends funds to it.
- **Dave** has inherited his father's bitcoin: a seed phrase and a note
  saying "the old wallet". He uses EntropyLab on an offline computer to try
  the common derivation paths and address types until he finds the addresses
  that hold the funds, so he knows exactly how to recover them.
- **Erin** is about to sign a large transaction prepared on her online
  computer. Before she signs, she transfers the PSBT and uses EntropyLab on
  an offline computer to load her seed, inspect the PSBT, and confirm where
  the money is going, how much comes back to her as change, and what fee she
  is paying.
- **Frank** wants a separate wallet on his phone for everyday spending, but
  doesn't want another backup to manage. He uses EntropyLab on an offline
  computer to derive a BIP-85 child seed from his main seed, so the phone
  wallet can always be recreated from the backup he already has.
- **Grace** runs Bitcoin workshops. On a test network, she walks her class
  from a handful of dice rolls to a seed phrase, derivation paths, keys, and
  addresses. She uses EntropyLab on an offline computer to show every step on
  screen instead of describing a black box.
- **Heidi** is a developer building wallet software. She uses EntropyLab on
  an offline computer to check her library's regtest derivations, comparing
  seeds, fingerprints, descriptors, and addresses step by step.
- **Ivan** writes a blog and wants to accept donations with one address he
  can publish once, without every donation landing on the same visible
  address. He uses EntropyLab on an offline computer to derive a Silent
  Payment address from his seed and confirm it matches the one his Silent
  Payments wallet shows. From a separate connected computer, he adds the DNS
  record EntropyLab prints to his domain so donors can pay a name instead of
  a long code.
- **Judy** runs a small shop and wants a payment address customers can
  recognise at a glance. She uses EntropyLab on an offline computer to search
  for a vanity address starting with a few letters of her shop's name,
  derived from her own seed, and writes down the passphrase or account number
  it finds. The address stays recoverable from her existing backup, with no
  new key to keep safe.

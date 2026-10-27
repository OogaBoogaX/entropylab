// Plain text only. English at each translating call is the catalog key.
// Lessons never receive session data, and hidden tools have no navigation ID.
export const featureGuideEntries = [
  ["calc-tool-intro", "keys"], ["msig-tool-intro", "multisig"],
  ["psbt-tool-intro", "inspect"], ["psbted-tool-intro", "edit"],
  ["nonce-tool-intro", "nonce"], ["bip85-tool-intro", "bip85"],
  ["sp-tool-intro", "silent"], ["vanity-tool-intro", "vanity"],
];

export function featureGuideLessons(hodlTText = (text) => text) {
  const glossary = {
    "basics-safety": [hodlTText("air gap"), hodlTText("A computer disconnected from every network, including Wi-Fi, Bluetooth, and cables. The browser cannot prove this isolation.")],
    "basics-family": [hodlTText("watch-only"), hodlTText("Public wallet information that can calculate addresses without spending keys. An xpub is an extended public key; a watch-only descriptor adds the address recipe. Both can reveal your activity.")],
    "basics-input": [hodlTText("entropy"), hodlTText("Unpredictability in your original input. Changing its format or hashing it does not add more.")],
    "basics-recipe": [hodlTText("derivation path"), hodlTText("The numbered route from a wallet's root key to an address. Keep it with the network, address type, and recovery instructions.")],
    "basics-check": [hodlTText("master fingerprint"), hodlTText("A short label for the root key. It helps recognition but can collide, so a matching fingerprint is not proof of identity.")],
    "basics-backup": [hodlTText("multisig policy"), hodlTText("The wallet recipe listing its signers and how many must agree to spend. Recovery needs this policy and enough independent signer backups.")],
  };
  // Explicit concept metadata: no step-index guesses about what a diagram teaches.
  const stages = {
    "basics-family": "keys", "basics-input": "input", "basics-recipe": "recovery", "basics-backup": "recovery",
    "keys-methods": "input", "keys-strength": "input", "keys-labs": "input", "settings-phrase": "recovery", "settings-path": "keys", "results-recognize": "addresses", "results-edit": "keys",
    "exports-public": "addresses", "exports-core": "recovery", "exports-transfer": "recovery", "bip85-recipe": "recovery", "bip85-use": "recovery",
  };
  const step = (id, title, body, check, limit, example = "", term = null) => ({ id, title, body, check, limit, example, term: term ?? glossary[id], diagramStage: stages[id] });
  return [
    { id: "basics", title: hodlTText("Start with the basics"), summary: hodlTText("Six short steps: secrets, your input, recovery, and checks."), steps: [
      step("basics-safety", hodlTText("Learn without entering secrets"),
        hodlTText("EntropyLab calculates wallet information from input you supply. It does not check balances, sign, or send payments. This guide needs no seed phrase or private key."),
        hodlTText("Keep real recovery material put away. Use only the public examples shown here."),
        hodlTText("The advanced-user startup warning still applies. Reading this guide does not make a device safe; an Offline label cannot prove an air gap.")),
      step("basics-family", hodlTText("Know what you can share"),
        hodlTText("An address tells someone where to pay you. Private keys authorize spending. A seed phrase is a set of recovery words that can rebuild many keys."),
        hodlTText("Share a receiving address when you want payment. Keep seed words, private keys, and required passphrases secret."),
        hodlTText("Watch-only cannot spend, but sharing it can expose many addresses and their activity.")),
      step("basics-input", hodlTText("You bring the randomness"),
        hodlTText("You supply dice rolls, coins, cards, or existing recovery material. EntropyLab follows a repeatable recipe; it never invents secret randomness."),
        hodlTText("Follow the input method's recommended amount. Recorded rolls plus the recipe can rebuild the wallet: protect them like seed words."),
        hodlTText("A long result can still come from weak input. Hashing and a dice fairness check cannot make predictable input secure.")),
      step("basics-recipe", hodlTText("The exact recipe selects your wallet"),
        hodlTText("Recovery uses the same seed words, any BIP39 passphrase, and wallet settings. A BIP39 passphrase is extra text combined with the words; a typo normally selects another valid wallet."),
        hodlTText("Preserve the exact passphrase and the path, network, and address type your wallet uses."),
        hodlTText("There is usually no wrong-password message. An empty-looking wallet may mean a different recipe, not lost funds.")),
      step("basics-check", hodlTText("Compare an address independently"),
        hodlTText("Use an independent trusted wallet or signing device to calculate the same first receiving address. Match the network and wallet settings, then compare the full address."),
        hodlTText("Check the complete address and master fingerprint. A matching picture or a few characters is not enough."),
        hodlTText("An address match checks that calculation. It does not prove a balance, a safe computer, or a safe transaction.")),
      step("basics-backup", hodlTText("Plan for this computer disappearing"),
        hodlTText("Keep the original recovery material, required passphrase, and wallet settings. Test recovery before relying on it. A multisig wallet also needs its policy and enough signer backups."),
        hodlTText("Could you recover if this computer and every open tab disappeared? A watch-only sheet cannot replace your secret backup."),
        hodlTText("Tabs are not backups. End Session cannot guarantee erasure of browser, operating-system, screenshot, or printed copies.")),
    ] },
    { id: "keys", tool: "calc", title: hodlTText("Keys: bring your own input"), summary: hodlTText("Choose an input method for your recovery material."), steps: [
      step("keys-methods", hodlTText("Pick the method that matches your material"),
        hodlTText("Key Station offers Dice rolls, Cards, Number bases, Seed phrase, and Private key. For coins choose Binary (Base 2) under Number bases; for hex choose Hexadecimal (Base 16)."),
        hodlTText("Choose the method that matches your material. Protect recorded dice rolls and their recipe like a seed phrase: together they can rebuild the wallet."),
        hodlTText("A valid input is not necessarily strong or safe. Recommended roll counts matter; a fairness test is only a statistical hint."),
        "", [hodlTText("What is hex?"), hodlTText("Hexadecimal writes numbers using 0–9 and a–f. It is an encoding, not extra randomness.")]),
      step("keys-strength", hodlTText("A valid input can still be weak"),
        hodlTText("Derive Key checks whether your input can be processed. That does not establish how unpredictable it was. A memorable sentence is not a substitute for independent randomness."),
        hodlTText("Read the selected method's instructions and warnings before deriving. Keep practice inputs separate from any real wallet."),
        hodlTText("More seed words or a different encoding cannot repair weak original input.")),
    ] },
    { id: "settings", tool: "calc", title: hodlTText("Keys: wallet settings"), summary: hodlTText("Understand passphrases, paths, networks, and address types."), steps: [
      step("settings-phrase", hodlTText("Words and passphrases have different jobs"),
        hodlTText("Seed words encode recovery material and check some typing mistakes. The optional BIP39 passphrase changes the wallet; every character matters. Supported phrase lengths are 12, 15, 18, 21, and 24 words."),
        hodlTText("Keep any required passphrase with your recovery plan, protected separately where appropriate. Test the exact combination."),
        hodlTText("A missing or mistyped BIP39 passphrase normally opens another valid wallet. More words cannot compensate for weak original input.")),
      step("settings-path", hodlTText("Choose the route your wallet expects"),
        hodlTText("Legacy, nested SegWit, native SegWit, and Taproot use different address recipes. Presets fill common paths. Custom paths, account indexes, branches, and ranges select wallet parts. Hardened steps need private material."),
        hodlTText("Use your wallet's documented preset. Record custom settings and check the header network."),
        hodlTText("Advanced fields can override defaults. A mainnet address and a test-network address are not interchangeable. Public multisig keys cannot derive hardened children."),
        "", [hodlTText("What is a derivation path?"), hodlTText("A sequence of numbered choices from a root key to a particular wallet branch or address.")]),
    ] },
    { id: "results", tool: "calc", title: hodlTText("Keys: results and stations"), summary: hodlTText("Recognize keys, check addresses, and edit station entries."), steps: [
      step("results-recognize", hodlTText("Read the public side first"),
        hodlTText("Results show a fingerprint, LifeHash picture, public wallet information, and addresses. Address-row QR buttons help comparison without retyping. The Private data hidden checkbox controls whether private recovery information is concealed. Revealing it exposes secrets."),
        hodlTText("Compare addresses independently; use fingerprints and pictures only as recognition aids."),
        hodlTText("Fingerprints are short and can collide. A matching picture is not authentication, and a QR code does not encrypt its contents.")),
      step("results-edit", hodlTText("Keep new and existing keys straight"),
        hodlTText("Name each station tab to recognize it. Edit Input reloads its recipe. Derive New Key adds a tab; Update Existing Key replaces the source after successful derivation. Removing a tab removes that session entry."),
        hodlTText("Check which key you are updating. Review the result and back up any changed recipe."),
        hodlTText("Updating seed, passphrase, or path can change the wallet. Tabs are not backups.")),
    ] },
    { id: "exports", tool: "calc", title: hodlTText("Recovery, exports, and QR"), summary: hodlTText("Save, share, and recover with the right exports."), steps: [
      step("exports-public", hodlTText("A descriptor is a wallet recipe"),
        hodlTText("A descriptor is an address recipe using keys and paths. An account xpub shares public derivation information for its branch. Prefixes such as zpub label the same key payload; the descriptor selects the recipe. Watch-only sheets help checks elsewhere."),
        hodlTText("Share watch-only for addresses. Check network, account path, and descriptor first."),
        hodlTText("Public wallet exports can reveal future addresses and activity. Watch-only cannot spend and cannot replace your secret recovery backup."),
        "", [hodlTText("What is an xpub?"), hodlTText("An extended public key: enough information to derive public child keys on its allowed branches, without the private spending keys.")]),
      step("exports-core", hodlTText("Move a recipe into Bitcoin Core"),
        hodlTText("wallet.dat packages descriptors for Bitcoin Core. Key Station defaults to watch-only; revealing private recovery material changes it to a spending export. The birthday sets how far Core scans. Choose New keys only for newly created material. Core does the scan."),
        hodlTText("Read the export label. If an old wallet looks empty, check settings and Core's rescan instructions."),
        hodlTText("Private wallet.dat permits spending. Valid files do not prove recovery or balance. Core may need a scan from genesis.")),
      step("exports-transfer", hodlTText("QR is another way to move information"),
        hodlTText("QR transfers displayed data to a camera. The PSBT editor splits large exports into animated parts for compatible scanners. Multisig also exports policy sheets, importdescriptors JSON, and BIP388 wallet policies."),
        hodlTText("Check scanner compatibility and verify the received information."),
        hodlTText("QR codes are not encryption. Printing, screenshots, clipboard history, and downloaded files can leave copies. Features and scanner support vary by export type.")),
    ] },
    { id: "multisig", tool: "msig", title: hodlTText("Multi Signature"), summary: hodlTText("Share wallet control between independent keys."), steps: [
      step("multisig-quorum", hodlTText("Set how many keys must agree"),
        hodlTText("A 2-of-3 wallet needs two of three keys to spend. MS Station uses co-signer public keys and origins to build its watch-only policy: threshold, address recipe, key order, and paths."),
        hodlTText("Before funding, independently verify the same policy and first address on every signer."),
        hodlTText("This station does not sign. Reusing one person's keys does not make independent custody. Losing enough keys to miss the threshold can make funds unrecoverable."),
        hodlTText("Three door keys, any two required: losing one may be survivable; losing two is not.")),
      step("multisig-backup", hodlTText("Back up the policy as well as the keys"),
        hodlTText("Export the descriptor or watch-only policy sheet so signers can agree on the wallet recipe. A compatible descriptor can repopulate MS Station. Bitcoin Core wallet.dat and importdescriptors JSON are watch-only here. Edit Input, Derive New Multisig, and Update Existing Multisig work like their Key Station counterparts."),
        hodlTText("Back up the full policy, co-signer public information, and enough independent signer secrets."),
        hodlTText("Private-key descriptors are refused. A sheet or fingerprint alone is not enough to spend. A different key order or path can make a different wallet.")),
    ] },
    { id: "inspect", tool: "psbt", title: hodlTText("PSBT Inspector"), summary: hodlTText("Read transaction files and the scope of their checks."), steps: [
      step("inspect-worksheet", hodlTText("Read where the payment is going"),
        hodlTText("A PSBT carries a proposed payment for signing. Check the recipient, change back to you, and fee. This example uses sats, the smallest bitcoin unit."),
        hodlTText("Independently check destination, amount, change, and fee before signing."),
        hodlTText("Amounts and previous-output information supplied by the file are not chain truth. Raw transactions without previous outputs cannot establish the fee. Ownership searches have a limited scope."),
        "", [hodlTText("What is change?"), hodlTText("Bitcoin spends whole previous outputs. The part not paid to the recipient or fee usually returns to an address in your wallet.")]),
      step("inspect-verdict", hodlTText("Completed is not safe-to-sign"),
        hodlTText("Checks report completed, problem, or incomplete. Sighash policies describe signature commitments. Nonstandard policies, unreadable signatures, or missing data can block a clean check. Inscription and OP_RETURN previews explain embedded data without fetching remote content."),
        hodlTText("Read each check's scope. Missing data and unsupported cases stay unanswered."),
        hodlTText("The inspector cannot certify a transaction safe, fetch chain information, sign, broadcast, create inscriptions, or tell you which sats you own.")),
    ] },
    { id: "signer", tool: "psbt", title: hodlTText("Check what the signer changed"), summary: hodlTText("Compare the file you sent with the file your signer returned."), steps: [
      step("signer-compare", hodlTText("Did the signer keep your payment intact?"),
        hodlTText("Save the exact PSBT you send to the signer. Compare it with the returned file: adding a signature should not redirect the payment. The example shows one change to stop and investigate."),
        hodlTText("Check destinations, amounts, change, and fee before signing, then compare the returned file before broadcasting."),
        hodlTText("A valid signature can authorize the wrong payment. An unchanged transaction can still have been wrong before it reached the signer.")),
      step("signer-use", hodlTText("Compare your own before and after copies"),
        hodlTText("In PSBT Inspector, put the returned PSBT in the main input. Open Check what the signer changed (optional), paste your saved original into PSBT you sent, and Inspect again."),
        hodlTText("Read the verdict and each finding: transaction changes, signatures, signer keys, change, and other data. Investigate unexplained differences."),
        hodlTText("Use your own saved original. A replacement supplied later by a compromised wallet or server can hide a change. Missing verification data remains unanswered.")),
    ] },
    { id: "fee-bump", tool: "psbt", title: hodlTText("Check a fee bump"), summary: hodlTText("See whether a replacement preserves the payment and raises the fee."), steps: [
      step("bump-compare", hodlTText("More fee, the same payment"),
        hodlTText("A fee bump proposes replacing an unconfirmed transaction. In this example the inputs and recipient stay the same. Your change falls by 500 sats and the fee rises by 500 sats."),
        hodlTText("Compare the recipient's full address and amount. A different recipient, a reduced payment, or redirected change needs investigation."),
        hodlTText("These numbers illustrate the idea. The real check also needs verified input amounts and enough wallet information to identify your change.")),
      step("bump-use", hodlTText("Check against the transaction you kept"),
        hodlTText("In PSBT Inspector, load the replacement PSBT. Open Check a fee bump (RBF) (optional), paste or upload your saved original transaction, then Inspect. RBF means replace-by-fee."),
        hodlTText("Use the original you signed or saved. Read the fee-bump verdict and its findings; unknown ownership or missing amounts must not be treated as approval."),
        hodlTText("A fee-only result describes the supplied comparison. It does not prove the original payment was intended, that the network will accept the replacement, or that it will confirm.")),
    ] },
    { id: "edit", tool: "psbt", title: hodlTText("PSBT Editor"), summary: hodlTText("Edit, compare, and export transaction worksheets."), steps: [
      step("edit-fields", hodlTText("Edit the worksheet, not the blockchain"),
        hodlTText("The editor opens PSBT v0 and v2. Select a diagram box to inspect inputs, outputs, or transaction fields. Edit structured fields or raw key-value data and export a rebuilt file. Validation checks supported serialization."),
        hodlTText("Keep the original. Check rebuilt outputs, fee, and signing state."),
        hodlTText("Editing can change payment destinations or invalidate signatures. A well-formed file is not a safe transaction. The editor never signs or broadcasts.")),
      step("edit-compare", hodlTText("Compare meaning, then verify independently"),
        hodlTText("Load a second PSBT to compare the transaction, signatures, and metadata separately. Reordering serialized fields is not treated as a meaningful change. Large edited PSBTs can be transferred as animated crypto-psbt QR parts to a compatible scanner."),
        hodlTText("Explain every difference before giving the edited file to a signer."),
        hodlTText("Comparison reports differences, not safety. Insane editing allows deliberately broken files for expert experiments; leave it off for ordinary work.")),
    ] },
    { id: "nonce", tool: "psbt", title: hodlTText("Nonce Inspector"), summary: hodlTText("Understand signature checks and their limits."), steps: [
      step("nonce-reuse", hodlTText("A repeated signing ingredient can be dangerous"),
        hodlTText("A signature uses a secret nonce. Reusing it incorrectly across messages with the same key can expose that key. The inspector checks supported ECDSA reuse, Taproot signatures, anti-exfil transcripts, and deterministic signing comparisons."),
        hodlTText("Distinguish confirmed, possible, and incomplete findings. Seek expert help for reuse."),
        hodlTText("No single check proves every signature safe. Missing keys, signatures, transcripts, or previous outputs can limit what can be verified.")),
      step("nonce-history", hodlTText("Keep history only if you need it"),
        hodlTText("Optional nonce history compares supported observations across files. Download it to keep it; upload to restore it. Some deterministic comparisons temporarily use a private key. Basic file analysis needs none."),
        hodlTText("Protect history files and run any private-key comparison only in a trusted offline environment."),
        hodlTText("History is correlation-sensitive metadata. Incomplete records cannot confirm reuse. A negative finding covers only the signatures and data actually checked.")),
    ] },
    { id: "bip85", tool: "bip85", title: hodlTText("BIP85 Child"), summary: hodlTText("Derive repeatable child recovery material."), steps: [
      step("bip85-recipe", hodlTText("One parent, many labeled recipes"),
        hodlTText("BIP85 derives child material from a parent root. Choose a seed phrase, key, hex, or password application and an index. The same complete recipe gives the same child. A BIP39 passphrase changes the parent and its children."),
        hodlTText("Record application, word count or length, child index, and parent recovery plan."),
        hodlTText("This transforms existing secret material; it does not add randomness. Anyone who obtains the parent can derive its children."),
        hodlTText("Think of numbered branches on a family tree. Knowing the root and the route lets you find the same branch again.")),
      step("bip85-use", hodlTText("Decide how each child will be recovered"),
        hodlTText("Select supported children in compatible tools through the key picker. Children can have their own backups. Removing one drops its options and clears sessions loaded from it. HD roots and individual keys have different tool support."),
        hodlTText("Test child recovery from its recipe or its own backup."),
        hodlTText("Parent compromise threatens children; losing the parent and the child's own backup can prevent recovery. Vanity cannot write a changed result back into an immutable child.")),
    ] },
    { id: "silent", tool: "sp", title: hodlTText("Silent Payments"), summary: hodlTText("Explore payment codes, sending calculations, and receiver checks."), steps: [
      step("silent-receive", hodlTText("Share a code instead of one ordinary address"),
        hodlTText("Silent Payments derives fresh destinations from a reusable recipient code and sender inputs. This tool derives codes, labels, and scan/spend descriptors from a root. Payment URIs and DNS text can publish the code."),
        hodlTText("Check wallet compatibility. Separate public payment codes from scan and spend secrets."),
        hodlTText("This calculator does not scan the blockchain or resolve payment names. Scan secrets affect privacy; spend secrets control money. Publishing DNS text happens outside EntropyLab.")),
      step("silent-send", hodlTText("Supply the transaction data yourself"),
        hodlTText("Supply inputs and recipient instructions to calculate Taproot outputs; supply outputs for receiver checks. A hybrid URI may carry an ordinary fallback, but this tool uses the selected Silent Payment instruction and identifies the unused fallback."),
        hodlTText("Verify inputs and recipient instructions. A compatible wallet builds and broadcasts the payment."),
        hodlTText("A calculated output is not a sent payment or a balance. Missing or incorrect supplied data can prevent a meaningful check. The guide never supplies sender keys.")),
    ] },
    { id: "vanity", tool: "vanity", title: hodlTText("Vanity Address"), summary: hodlTText("Search your existing key for a chosen address prefix."), steps: [
      step("vanity-search", hodlTText("Choose a look, then search"),
        hodlTText("Vanity starts from your existing key. Passphrase search tries counter-based passphrase extensions; derivation search tries account indexes. Each candidate is calculated normally and checked against your prefix. More characters usually mean much more work."),
        hodlTText("Review method, prefix rules, range, and estimate. Start explicitly; the lesson never searches."),
        hodlTText("An attractive prefix adds no security. Time estimates are uncertain, and no match is guaranteed within your range. EntropyLab never invents secret randomness.")),
      step("vanity-save", hodlTText("A match may be a different wallet"),
        hodlTText("A match gives the passphrase or account setting for that address. Update key explicitly applies it to Key Station and re-derives. Children remain unchanged. Resuming multi-worker searches may repeat work without skipping unfinished gaps."),
        hodlTText("Preserve the exact found passphrase or path. Independently check and back up the wallet."),
        hodlTText("Your old settings may not recover the vanity address. Found secrets stay in session memory until cleared; a copied address alone is not recovery material.")),
    ] },
    { id: "labs", tool: "calc", title: hodlTText("Advanced: input transformations"), summary: hodlTText("Understand method sync and the Brain wallet experiment."), steps: [
      step("keys-labs", hodlTText("Understand previews and lab modes"),
        hodlTText("Sync entropy across methods shows other representations of your input; it starts off, and hashed inputs sync one way. Brain wallet under Private key hashes exact typed text into recovery material. It is separate from a BIP39 passphrase."),
        hodlTText("Explore transformations with worthless examples separate from real wallets."),
        hodlTText("Human-chosen text is often guessable even after hashing into 24 words. The guide never fills seed fields or creates demo wallets.")),
    ] },
    { id: "session", title: hodlTText("Session and safety controls"), summary: hodlTText("Understand reveal, clear, End Session, and local signals."), steps: [
      step("session-controls", hodlTText("Keep secrets out of unnecessary places"),
        hodlTText("Reveal exposes private information. On-screen keyboards offer another entry method; theme and language change presentation. Offline reference links open as QR codes for another device, keeping this computer from navigating online."),
        hodlTText("Hide secrets before sharing the screen. Check clipboard, downloads, and print copies."),
        hodlTText("On-screen keyboards cannot defeat malware. Reveal and clear controls cannot erase screenshots, clipboard history, printer storage, or every browser copy.")),
      step("session-end", hodlTText("End deliberately and understand the signals"),
        hodlTText("The Security log records local browser connectivity and translation signals without wallet data or probes. Clear removes session entries. End Session wipes what it can, retires modules, clears a clipboard it wrote when permitted, and requests tab closure."),
        hodlTText("Save recovery information securely first. Close the tab or quit if it stays open."),
        hodlTText("Offline status and translation detection are best-effort signals. Startup tests and memory cleanup have limits. Nothing in this guide certifies the computer safe.")),
    ] },
  ];
}

export function featureGuideRoutes(hodlTText = (text) => text) {
  return [
    { id: "wallet", title: hodlTText("Understand wallets"), summary: hodlTText("Learn what to protect, choose an input, and check an address."), lessons: ["basics", "keys", "results"] },
    { id: "recovery", title: hodlTText("Prepare for recovery"), summary: hodlTText("Distinguish public exports from spending backups and plan signer recovery."), lessons: ["settings", "exports", "multisig", "session"] },
    { id: "transaction", title: hodlTText("Understand a transaction"), summary: hodlTText("Read a payment, check a signer or fee bump, and understand the limits."), lessons: ["inspect", "signer", "fee-bump", "edit", "nonce"] },
    { id: "advanced", title: hodlTText("Explore advanced tools"), summary: hodlTText("Learn child recovery material, Silent Payments, and vanity search limits."), lessons: ["bip85", "silent", "vanity", "labs"] },
  ];
}
export function featureGuideCheck(id, hodlTText) {
  const checks = {
    "basics-backup": [hodlTText("Which lets someone spend bitcoin?"), [hodlTText("A receiving address"), hodlTText("A private key")], 1, hodlTText("An address is a destination you can share. A private key grants spending power and must stay secret.")],
    "exports-transfer": [hodlTText("Does a watch-only sheet replace a secret recovery backup?"), [hodlTText("Yes"), hodlTText("No")], 1, hodlTText("Watch-only helps you check addresses. Recovery still needs the original secrets and wallet settings.")],
    "inspect-verdict": [hodlTText("Does a completed check mean a transaction is safe to sign?"), [hodlTText("Yes"), hodlTText("No")], 1, hodlTText("A check covers only its stated scope. Independently verify the destination, amount, change, and fee.")],
    "signer-use": [hodlTText("The returned transaction is unchanged. Does that prove the original payment was the one you intended?"), [hodlTText("Yes"), hodlTText("No")], 1, hodlTText("The comparison checks for changes. You still need to verify the original destination, amount, change, and fee independently.")],
    "bump-use": [hodlTText("The fee rose, but the recipient changed. Is that only a fee bump?"), [hodlTText("Yes"), hodlTText("No")], 1, hodlTText("A higher fee does not excuse a different payment destination. Stop and investigate the changed recipient.")],
    "bip85-use": [hodlTText("Can someone with the parent derive its BIP85 children?"), [hodlTText("Yes"), hodlTText("No")], 0, hodlTText("Protect the parent: access to it threatens all children derived from it.")],
  };
  return checks[id];
}

// Public teaching material only: no keys, addresses, PSBT bytes, or calculations.
// Each table is read-only and never supplies values to the app's real tools.
export function featureGuideExample(id, hodlTText = (text) => text) {
  const examples = {
    "basics-family": {
      caption: hodlTText("Practice example: which information can you share?"),
      columns: [hodlTText("Information"), hodlTText("How to treat it")],
      rows: [
        [hodlTText("Receiving address"), hodlTText("Share to receive a payment")],
        [hodlTText("Seed words or private key"), hodlTText("Keep secret: spending power")],
        [hodlTText("Watch-only information"), hodlTText("Cannot spend; reveals wallet activity")],
      ],
    },
    "basics-recipe": {
      caption: hodlTText("Practice example: same seed words, different passphrase"),
      columns: [hodlTText("Passphrase supplied"), hodlTText("Result")],
      rows: [
        [hodlTText("Your original exact text"), hodlTText("Your original wallet")],
        [hodlTText("One-character typo"), hodlTText("Normally a different valid wallet")],
      ],
    },
    "inspect-worksheet": {
      caption: hodlTText("Practice example: where 100,000 sats go"),
      columns: [hodlTText("Part of the payment"), hodlTText("Amount")],
      rows: [
        [hodlTText("Total input"), hodlTText("100,000 sats")],
        [hodlTText("To the recipient"), hodlTText("60,000 sats")],
        [hodlTText("Change back to you"), hodlTText("39,000 sats")],
        [hodlTText("Fee: input minus outputs"), hodlTText("1,000 sats")],
      ],
    },
    "signer-compare": {
      caption: hodlTText("Practice example: the amount stayed, the recipient changed"),
      columns: [hodlTText("Check"), hodlTText("Before"), hodlTText("After")],
      rows: [
        [hodlTText("Recipient"), hodlTText("Recipient A"), hodlTText("Different recipient B")],
        [hodlTText("Payment"), hodlTText("60,000 sats"), hodlTText("60,000 sats")],
        [hodlTText("Change"), hodlTText("39,000 sats"), hodlTText("39,000 sats")],
        [hodlTText("Fee"), hodlTText("1,000 sats"), hodlTText("1,000 sats")],
      ],
    },
    "bump-compare": {
      caption: hodlTText("Practice example: 500 sats move from change to fee"),
      columns: [hodlTText("Check"), hodlTText("Original"), hodlTText("After bump")],
      rows: [
        [hodlTText("Total input"), hodlTText("100,000 sats"), hodlTText("100,000 sats")],
        [hodlTText("Recipient"), hodlTText("Recipient A"), hodlTText("Recipient A")],
        [hodlTText("Payment"), hodlTText("60,000 sats"), hodlTText("60,000 sats")],
        [hodlTText("Change"), hodlTText("39,000 sats"), hodlTText("38,500 sats")],
        [hodlTText("Fee"), hodlTText("1,000 sats"), hodlTText("1,500 sats")],
      ],
    },
  };
  return Object.hasOwn(examples, id) ? examples[id] : null;
}

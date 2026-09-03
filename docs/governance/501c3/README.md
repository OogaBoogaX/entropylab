# EntropyLab — 501(c)(3) Legal/Governance Docs

Context for picking this up in Claude Code (or handing to a lawyer/accountant).

## Project
EntropyLab — open-source, zero-dependency, air-gapped Bitcoin key/wallet calculator.
- Repo: https://github.com/w-s-bitcoin/entropylab
- Site: https://entropylab.online
- License: MIT
- Co-created by **Mr.Hodl** and **Wicked**

## What this package is
Draft governance/legal documents for structuring EntropyLab as a **standalone 501(c)(3) nonprofit**, adapted from earlier drafts written for an LLC-taxed-as-partnership route. All three files still contain `[TBD]` fields that need real decisions before anything goes to an attorney for filing.

| File | Purpose | Replaces (LLC version) |
|---|---|---|
| `formation-checklist.md` | Sequenced steps: board recruitment → incorporation → EIN → Form 1023/1023-EZ → bylaws → charitable registration → banking/treasury → ongoing 990 compliance | `entropylab-llc-formation-checklist.md` |
| `bylaws-draft.md` | Board structure, officer roles, meeting/voting rules, IRC §4958 compensation-approval process, conflict of interest policy annex, IP/MIT license continuity, required IRS dissolution clause | `entropylab-llc-operating-agreement-draft.md` |
| `contributor-comp-policy.md` | How paid contributors get approved and paid, built around the "rebuttable presumption of reasonableness" process rather than simple recusal | `entropylab-contributor-comp-policy.md` |

## Why 501(c)(3) instead of the LLC that was previously chosen
The prior working session had settled on an **LLC taxed as a partnership** and explicitly ruled out fiscal sponsorship and standalone 501(c)(3) (deprioritized due to private-inurement risk with only two founders and no independent board). This package revisits the 501(c)(3) path at the user's request — it is not a final decision, just the alternate structure worked out in full.

## The one decision that gates everything
**Recruit at least one, ideally two, independent board members** before or immediately after incorporating. A board of just Mr.Hodl and Wicked — who are also the people most likely to request paid work — is the exact fact pattern IRS private inurement / intermediate sanctions (IRC §4958) rules are built to catch. Every other governance mechanism in these docs (compensation approval, treasury multisig, conflict-of-interest recusal) assumes this gets solved first.

## Other open [TBD] items across the docs
- Formation state
- Board size and independence threshold (bylaws §2.2)
- Officer roles/assignments (bylaws Article 4)
- Multisig treasury key holders, including whether an independent director holds a key (bylaws §7.4)
- Dissolution recipient — name one now or leave to future Board determination (bylaws §10.2)
- Repo/domain disposition on dissolution (bylaws §10.3)
- Form 1023 vs. 1023-EZ eligibility (depends on projected gross receipts ≤$50k/yr and assets ≤$250k — confirm current IRS thresholds)

## Also referenced but not included in this package
- `opensats-application-entropylab.md` — OpenSats grant application draft (fiscal sponsorship path; useful as source material for the Form 1023 narrative's factual/technical description, but written for a grantmaker, not the IRS)
- LLC-route documents (operating agreement, comp policy, formation checklist) — kept from the earlier session as the parallel-track alternative

## Reminder
None of this has been reviewed by a lawyer or accountant. Treat every `[TBD]` as a real decision the founders need to make, and get the bylaws + Articles of Incorporation reviewed by nonprofit counsel in the formation state before filing or adopting anything.

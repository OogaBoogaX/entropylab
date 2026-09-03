# EntropyLab — 501(c)(3) Formation Checklist

*Route: standalone 501(c)(3) nonprofit corporation. This is a materially bigger lift than the LLC path — more filings, an ongoing independent board requirement, and public disclosure obligations (Form 990, conflict-of-interest policy on file) that don't exist for an LLC. Sequenced roughly in the order steps need to happen. Items marked [TBD] are decisions to lock in before or during that step.*

---

## 0. The one decision that shapes everything else

- [ ] **Recruit at least one, ideally two, genuinely independent board members before or immediately after incorporating.** A board consisting only of Mr.Hodl and Wicked — who are also the people most likely to request contributor payment — is the exact fact pattern the IRS's private inurement and intermediate sanctions rules are built to catch. This isn't optional paperwork; without an independent voice on compensation and major decisions, the entity's tax-exempt status is genuinely at risk if either founder is ever paid. This was flagged as the reason standalone 501(c)(3) was deprioritized earlier — revisit that concern here rather than treating it as solved by structure alone.
- [ ] Identify candidates: a respected figure in Bitcoin/security open-source, a nonprofit-experienced advisor, or someone from an allied project (e.g., a maintainer at another Bitcoin-FOSS project with no financial stake in EntropyLab). They don't need deep technical expertise — they need independence and a willingness to actually review compensation requests.

## 1. Pre-formation decisions

- [ ] **Formation state.** Nonprofits generally incorporate in the state where they'll operate (no Delaware-style advantage the way there sometimes is for for-profits). Check your state's nonprofit corporation filing requirements and fees.
- [ ] **Organization name.** Confirm "EntropyLab" (or a formal legal name, e.g., "EntropyLab Foundation") is available with your Secretary of State and doesn't conflict with existing nonprofits.
- [ ] **Initial board composition and size.** Lock in at least 3 directors before filing if possible (some states require a minimum of 3 for nonprofits; even where 1–2 is legally allowed, 2-founder-only boards are the inurement risk flagged above). [TBD: names, whether Mr.Hodl/Wicked use legal names or pseudonymous arrangements — check your state's disclosure rules, since nonprofit officer/director info is often more public than LLC member info.]
- [ ] **Registered agent.** Required in every state; a commercial registered agent service is worth it if board members prefer not to use personal addresses as public record.
- [ ] **Statement of purpose.** Needs to tie to a recognized IRS-exempt purpose (educational/charitable — open-source security education and tooling generally qualifies under "educational," similar to how other Bitcoin-FOSS nonprofits and fiscal sponsors are organized). Draft this carefully; it drives both the Articles of Incorporation and the Form 1023 narrative.

## 2. State incorporation

- [ ] File **Articles of Incorporation** with the Secretary of State. Must include IRS-required language: a statement of exempt purpose, and a **dissolution clause** committing remaining assets to another 501(c)(3) or governmental entity (not to individuals) — the IRS will reject Form 1023 without this exact language in the Articles.
- [ ] Pay the state filing fee (varies, typically $25–150 for nonprofits — usually cheaper than LLC filing).
- [ ] Note the incorporation date — needed for the EIN application and Form 1023.

## 3. Federal tax-exempt application

- [ ] **Apply for an EIN** (free, IRS.gov) as soon as incorporated — needed for the bank account and the exemption application itself.
- [ ] **Determine Form 1023 vs. Form 1023-EZ eligibility.** 1023-EZ is a shorter, cheaper application, but only available if projected annual gross receipts are ≤$50,000 for the next 3 years and total assets are ≤$250,000, among other eligibility rules. At EntropyLab's likely donation/grant scale this may qualify initially — check current IRS eligibility worksheet, since thresholds and rules can change.
- [ ] **Draft the Form 1023 narrative** (or 1023-EZ, which has less narrative but still requires accurate activity descriptions). The existing OpenSats application draft is a useful *source* for factual/technical content (what the tool does, why it matters, security significance) but needs reworking — a 1023 narrative is written for the IRS, not a grantmaker, and needs to affirmatively demonstrate the activity serves a public/educational purpose rather than the founders' private interests.
- [ ] Pay the IRS user fee ($275 for 1023-EZ, $600 for full 1023, as of recent years — confirm current fee on IRS.gov before filing).
- [ ] Expect processing time: 1023-EZ often resolves in weeks to a couple months; full 1023 can take several months to over a year.

## 4. Governance documents

- [ ] Finalize and **adopt Bylaws** (draft provided separately) — fill in all [TBD] fields: board size, officer roles, meeting cadence, voting thresholds.
- [ ] Adopt a **Conflict of Interest Policy** (included as an annex to the Bylaws draft) — the IRS Form 1023 specifically asks whether you've adopted one and will often accept the IRS's own template language; having one in place before filing strengthens the application.
- [ ] Adopt the **Contributor Compensation Policy** (rewritten separately around nonprofit rules) — formally approved by the board, with independent-director sign-off documented in meeting minutes.
- [ ] Have both Bylaws and Articles reviewed by a lawyer familiar with nonprofit formation in your state before filing/adopting — worth the spend here more than almost anywhere else in this process, given the personal-liability and exempt-status stakes.

## 5. State-level follow-up

- [ ] **State charitable solicitation registration.** Most states require nonprofits to register *before* soliciting donations from their residents (this is separate from IRS exemption and easy to overlook). Since EntropyLab solicits donations online/nationally, check whether multi-state registration is realistically needed — many small nonprofits register in their home state first and expand as needed; a lawyer can advise on risk tolerance here.
- [ ] **State income/franchise tax exemption.** Federal 501(c)(3) status doesn't automatically exempt you from state taxes in every state — some require a separate application.
- [ ] **Sales tax exemption** (if applicable) — usually low priority for a software project with no physical sales.

## 6. Banking and treasury

- [ ] Open a **nonprofit bank account** in the entity's name (needs EIN + Articles of Incorporation, and often a board resolution authorizing the account).
- [ ] Set up the **BTC treasury**, ideally multisig, with key holders including at least one independent board member if feasible — mirrors the "no two founders alone control the money" principle that runs through this whole restructuring.
- [ ] Decide whether the organization holds BTC directly or converts to USD on receipt — nonprofits still need to record fair-market-value USD at time of receipt for accounting/990 purposes even if they hold BTC.

## 7. Bookkeeping and ongoing compliance

- [ ] Set up bookkeeping tracking donations, grants, and contractor payments separately — needed for both internal governance and the annual **Form 990** (or 990-EZ/990-N depending on size), which is public.
- [ ] Calendar recurring deadlines:
  - **Form 990** family — due the 15th day of the 5th month after fiscal year-end (extendable), and publicly disclosable once filed
  - State annual report / registered agent renewal
  - Charitable solicitation registration renewals (varies by state, often annual)
- [ ] Calendar a recurring board meeting (quarterly is typical for small nonprofits) with minutes kept — minutes are your paper trail that compensation and major decisions went through the independent board, not just the founders.

## 8. Public-facing updates

- [ ] Update entropylab.online and the GitHub repo/README to reflect the new entity and its EIN/exempt status once granted — donors will want this to claim deductions.
- [ ] Publish (or be ready to provide) the organization's Form 1023/1023-EZ and eventual Form 990s if requested — 501(c)(3)s are required to make these available for public inspection.

---

### First three things to actually do:
1. Identify and confirm at least one independent board candidate (Section 0) — this gates everything else meaningfully
2. Draft Articles of Incorporation with required IRS dissolution language and file with the state (Section 2)
3. Apply for EIN once incorporation is confirmed (Section 3)

Bylaws, the Compensation Policy, and the Form 1023 narrative can be worked on in parallel once the board question is settled.

# EntropyLab — Bylaws (Draft Skeleton)

*This replaces the LLC operating agreement in a nonprofit structure — nonprofits have Bylaws and a Board of Directors instead of Members and an operating agreement. This is a starting skeleton, not a finished legal document. Have a lawyer licensed in your formation state review and finalize before adoption — Bylaws are load-bearing here in the same way the operating agreement would have been for the LLC, and the IRS reviews them (or asks about their contents) as part of Form 1023.*

---

## Article 1 — Name, Purpose & Offices

1.1 **Name.** The organization shall be known as "EntropyLab" [or a formal legal name, e.g., "EntropyLab Foundation"] (the "Organization").

1.2 **Purpose.** The Organization is organized exclusively for charitable and educational purposes within the meaning of Section 501(c)(3) of the Internal Revenue Code, specifically to develop, maintain, and distribute open-source, offline-first Bitcoin self-custody software and related security education, and to support this work through donations and grants.

1.3 **Limitations.** No part of the net earnings of the Organization shall inure to the benefit of any director, officer, or private individual. No substantial part of the Organization's activities shall be devoted to attempting to influence legislation, and the Organization shall not participate in any political campaign.

1.4 **Principal Office.** [TBD — registered agent address if directors are remote/pseudonymous.]

---

## Article 2 — Board of Directors

2.1 **Governing Body.** The Organization has no members (in the corporate-membership sense); it is governed by a Board of Directors.

2.2 **Number and Composition.** The Board shall consist of no fewer than [3] directors. **At least [one-third / a majority]** of directors shall be Independent Directors — defined as individuals with no financial interest in any compensation paid by the Organization and no family or business relationship with a compensated director, officer, or contractor. [Decide the exact threshold; more independence is a stronger safeguard and a stronger signal to the IRS, but don't set a number you can't realistically staff.]

2.3 **Initial Directors.** [TBD — Mr.Hodl, Wicked, plus [name(s)] of independent director(s).]

2.4 **Term.** Directors serve [1–3 year, staggered/renewable] terms. [TBD.]

2.5 **Removal and Vacancies.** A director may be removed [with/without cause] by a vote of [two-thirds] of the remaining directors. Vacancies are filled by the remaining Board.

2.6 **Compensation of Directors.** Directors may be compensated for scoped work performed for the Organization (e.g., engineering, security review) under the Contributor Compensation Policy, but **serving as a director does not itself carry compensation**, and any director being compensated for other work must recuse from Board votes approving that compensation per Article 6.

---

## Article 3 — Meetings & Voting

3.1 **Regular Meetings.** The Board shall meet at least [quarterly].

3.2 **Special Meetings.** May be called by [any director / the Chair] with [X days'] notice.

3.3 **Quorum.** A majority of directors then in office constitutes a quorum. [Consider requiring that a quorum include at least one Independent Director for votes involving compensation — see Article 6.]

3.4 **Voting.** Each director has one vote. Except as otherwise specified (see Article 6 for compensation votes and Article 10 for amendments/dissolution), action requires a majority of directors present at a quorate meeting.

3.5 **Action Without Meeting.** The Board may act by unanimous written consent in lieu of a meeting.

3.6 **Minutes.** Minutes shall be kept for every meeting, including votes taken, directors recused and why, and the basis for any compensation decision (see Article 6). This is the Organization's paper trail if a funder, donor, or the IRS ever asks how decisions were made.

---

## Article 4 — Officers

4.1 **Officers.** The Board shall elect a [President/Chair], [Secretary], and [Treasurer] (roles may combine on a small board, except that the same person should not hold both roles that check each other, e.g., Treasurer and Chair, if avoidable).

4.2 **Duties.** [TBD — standard duties: Chair presides at meetings; Secretary keeps minutes and corporate records; Treasurer oversees financial records, tax filings, and works with any external bookkeeper/accountant.]

4.3 **Term.** Officers serve [1-year renewable] terms, elected annually by the Board.

---

## Article 5 — Committees

5.1 **Optional Committees.** The Board may establish committees (e.g., a Compensation Committee, Audit Committee) and delegate specific functions, provided any committee approving compensation includes at least one Independent Director and excludes any director whose own compensation is under discussion.

---

## Article 6 — Compensation Approval Process (Rebuttable Presumption of Reasonableness)

*This article exists to protect both the Organization's exempt status and the individual directors/officers from IRS "intermediate sanctions" excise tax exposure under IRC §4958, which applies personally to "disqualified persons" (which includes founders/directors) who receive excess benefit from the Organization. Following this process creates a rebuttable presumption that compensation is reasonable — meaning the IRS bears the burden of proving otherwise, rather than the Organization.*

6.1 **Independent Approval.** Any compensation paid to a director, officer, or other "disqualified person" (a term of art under §4958 covering those with substantial influence over the Organization — this includes both founders regardless of title) must be approved **in advance by a body composed entirely of individuals with no conflict of interest in the specific payment** — i.e., the Independent Directors, or a Compensation Committee composed of them. A director/officer with a financial interest in the payment **may not be present for the discussion or vote**, not merely abstain.

6.2 **Comparability Data.** Before approving, the approving body must rely on appropriate comparability data — e.g., published rates for comparable open-source security/development work, compensation data from similar-sized Bitcoin-FOSS nonprofits or fiscally sponsored projects (OpenSats/Brink grant sizes for similar scoped work are a reasonable proxy), or independent compensation surveys if available.

6.3 **Contemporaneous Documentation.** The approving body must document, at or before the next meeting following the decision: the terms approved and date, the members present and voting, the comparability data relied on, and how it was obtained. This documentation must be contemporaneous — created before the payment is made or within a reasonable time after — not reconstructed later.

6.4 **Minimum Independent Body.** If at any time the Organization has fewer than [two] Independent Directors able to form a quorum for a compensation vote, no compensation to a disqualified person may be approved until an additional independent director is seated or a qualified outside advisor is engaged to fill this role on an ad hoc basis. **This is a harder floor than the LLC's "get a third disinterested party" fallback** — under §4958, an inadequately independent approval process can itself undermine the rebuttable presumption even if the amount was objectively reasonable.

6.5 **Prohibition on Private Inurement.** Notwithstanding any approval under this Article, no compensation arrangement may result in net earnings inuring to the benefit of any director, officer, or founder beyond reasonable payment for services actually rendered. Guaranteed profit-sharing, equity-like arrangements, or payments not tied to scoped, documented work are prohibited regardless of approval, since these would risk the Organization's exempt status outright rather than merely being subject to excise tax.

---

## Article 7 — Financial Controls & Records

7.1 **Fiscal Year.** [TBD — calendar year is simplest.]

7.2 **Books and Records.** The Organization shall maintain accurate financial records, including all documentation required under Article 6 and the Contributor Compensation Policy, BTC/USD fair-market-value records at time of each transaction, and records sufficient to prepare Form 990.

7.3 **Annual Filings.** The Treasurer (or an engaged bookkeeper/accountant) shall ensure Form 990 (or 990-EZ/990-N as applicable) is filed annually and made available for public inspection as required by law.

7.4 **BTC Treasury.** The Organization's BTC treasury shall be held in a multisignature wallet requiring [2-of-3, with at least one key held by or accessible to an Independent Director] signatures for outbound transactions. [Strongly recommend including an independent key holder here, mirroring the independent-approval principle in Article 6 — a treasury controlled entirely by the two founders undercuts the independence built into the compensation process.]

---

## Article 8 — Intellectual Property

8.1 **Ownership.** All code, documentation, and other work product created by directors, officers, or contractors in the course of Organization business is owned by the Organization, except as licensed out under the project's chosen open-source license.

8.2 **License Continuity.** The Organization shall continue to release EntropyLab under the MIT License (or such other OSI-approved license as the Board unanimously approves). Nothing in these Bylaws restricts the public's rights under that license.

---

## Article 9 — Conflict of Interest Policy

*(Adopt as an annex; the IRS Form 1023 specifically asks whether one exists and generally accepts language modeled on the IRS's own sample policy — the summary below tracks that model.)*

9.1 **Purpose.** To protect the Organization's interest when a director, officer, or contributor with decision-making authority may benefit personally from a transaction.

9.2 **Duty to Disclose.** Any director or officer with a financial interest in a proposed transaction (including but not limited to their own compensation) must disclose that interest to the Board before discussion.

9.3 **Recusal.** The interested individual shall not be present for Board discussion or vote on the matter (beyond answering factual questions if invited), consistent with Article 6.1.

9.4 **Annual Disclosure.** Each director and officer shall annually disclose any known financial interests that could give rise to a conflict.

9.5 **Compliance.** The Board shall periodically review compliance with this policy, including whether compensation arrangements followed the process in Article 6.

---

## Article 10 — Amendment & Dissolution

10.1 **Amendment.** These Bylaws may be amended by a [two-thirds] vote of the Board, provided any amendment weakening the independent-approval requirements in Article 6 requires the same independent-quorum protections that apply to compensation votes — i.e., the people who'd benefit from loosening the rules shouldn't be the ones loosening them.

10.2 **Dissolution.** Upon dissolution, after paying or making provision for all liabilities, the Organization's remaining assets shall be distributed exclusively to one or more organizations then qualified as exempt under Section 501(c)(3) of the Internal Revenue Code, or to a governmental entity for a public purpose, as determined by the Board — **never to any director, officer, or private individual.** [TBD: name a preferred recipient now, e.g., another Bitcoin-FOSS nonprofit, or leave to the Board's determination at the time — either is acceptable to the IRS as long as the class of eligible recipients is exempt orgs.]

10.3 **Treasury/Repo Disposition on Dissolution.** [TBD — same practical question as under the LLC draft: does the GitHub repo/domain transfer to a successor steward organization, another Bitcoin-FOSS nonprofit, or the individual founders? Note: transferring IP/domain assets to the founders personally on dissolution would itself need to be at fair value and carefully documented to avoid it looking like disguised private inurement.]

---

**Adopted by the Board of Directors**

| Director | Role | Signature | Date |
|---|---|---|---|
| Mr.Hodl | | _______________ | _______ |
| Wicked | | _______________ | _______ |
| [Independent Director] | | _______________ | _______ |

---

### Open items to resolve before finalizing (flagged throughout as [TBD]):
- [ ] Identify and confirm independent director(s) — gates most other decisions
- [ ] Board size and exact independence threshold (2.2)
- [ ] Officer roles and who holds them (Article 4)
- [ ] Multisig key holders including independent-key question (7.4)
- [ ] Dissolution recipient — name one now or leave to future Board determination (10.2)
- [ ] Repo/domain disposition on dissolution (10.3)
- [ ] Attorney review in your formation state before adoption

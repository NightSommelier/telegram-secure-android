# Revision 2 review record

`../REVIEW-DECISION.md` is still **CHANGES REQUIRED**. This mapping does not
close an issue merely by creating an evidence template.

| Item | r2 evidence | Owner | Closure criterion | Status |
|---|---|---|---|---|
| IR1 ratchet choice | `RATCHET-BACKEND-DOSSIER.md` | security + legal | named approved/pinned backend passes every dossier gate | Open |
| IR2 protocol/CFS review | clarifications + fixtures + two consumers | independent reviewer | written independent review and reproduced fixtures | Open |
| IR3 Telegram boundary | transport packet | Telegram integration owner | two-account evidence and written feasibility decision | **Open** |
| IR4 Keystore/storage | lifecycle template + packet | Android security owner | selected store/device matrix and transactional test evidence | Open |
| IR5 complete fixtures | `fixtures.json`, negatives, consumers | security owner | both consumers pass all applicable vectors; ratchet/storage after selection | In progress |
| IR6 carrier/fallback | UX packet + clarifications | product + legal | written product/legal decision and accepted flow evidence | **Open** |
| r1 CFS omissions | CFS validation table | protocol reviewer | review accepts exact constraints | In progress |
| r1 transcript ambiguity | transcript correction + four-DH fixture | protocol reviewer | independently reproduced handshake | In progress |
| r1 send uncertainty | adapter contract + packet | Telegram owner | durable-send evidence | Open |

Ratchet and storage fixtures are explicitly pending the selected backend and
approved storage policy; this is a blocker, not a waiver.

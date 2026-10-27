# Demo video script (about 2 minutes)

Screen-record a terminal and a browser. Speak plainly; the visuals carry the detail.

| Time | On screen | Say |
| --- | --- | --- |
| 0:00–0:15 | Title card: "FROST Interop Lab" | "FROST lets a group hold shielded ZEC together, so no single person can spend it. Six teams are building FROST wallets for Zcash. Nobody has checked whether they work together." |
| 0:15–0:35 | Forum thread quote: "each wallet is defining its own coordinator-to-signer messages and its own share backups" | "The builders say it themselves: every wallet defines its own messages and backups. So a co-signer from one app can't sign for another, and a backup may not restore elsewhere." |
| 0:35–0:55 | `npm run demo`, step 1 | "Worse: two key derivations are in use today. Same group, same keys, different address. Restore in the wrong wallet and you see a zero balance." |
| 0:55–1:20 | Demo steps 2–3 | "The lab gives every implementation the same shared vectors and the same random inputs, then compares every pair. Our TypeScript and Python implementations, written independently, agree on all of it." |
| 1:20–1:40 | Demo step 4, then `reports/report.html` | "Here's a deliberately broken implementation. The lab catches both bugs: a field reduced modulo the wrong prime, and a backup that should have been rejected." |
| 1:40–1:55 | ADAPTERS.md | "Any wallet plugs in with a small adapter: JSON lines, any language, an afternoon's work." |
| 1:55–2:10 | README roadmap | "Next: real wallet adapters, then live signing interop, where signers from different wallets sign one real transaction. FROST Interop Lab: so Zcash wallets work together." |

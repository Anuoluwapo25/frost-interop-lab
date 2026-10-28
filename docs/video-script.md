# Demo video script (about 2 minutes)

Screen-record a terminal and a browser. Before recording, build the Rust adapter (`cd adapters/orchard-rust && cargo build --release`) and run `npm run demo` once so it's warm. The lab step takes about 30 seconds; cut the wait in editing.

| Time | On screen | Say |
| --- | --- | --- |
| 0:00–0:12 | Title card: "FROST Interop Lab" | "FROST lets a group hold shielded ZEC together, so no single person can spend it. Six teams are building FROST wallets for Zcash. Nobody has checked whether they work together." |
| 0:12–0:30 | `npm run demo`, step 1 | "Here's why that matters. Two key derivations are in use today. Same group, same keys, different address. Restore in the wrong wallet and you see a zero balance." |
| 0:30–0:50 | Steps 2–3 | "The lab gives every implementation the same vectors and the same random inputs, then compares every pair. That includes the official Zcash crates and ZF's FROST library. Key derivation, backups, and FROST signing, where each group's key shares are split across two implementations." |
| 0:50–1:10 | Step 4 | "This implementation has four realistic bugs, and the lab catches all of them. A field reduced modulo the wrong prime. A backup that should be rejected. A signer that ignores the spend's randomizer, blamed by name. A verifier that accepts a malleable signature." |
| 1:10–1:40 | Step 5 (or `node src/cli.ts spend`) | "And the end to end. One three-of-four FROST group: a share in ZF's Rust FROST, one in Python, one in TypeScript. The official orchard crate builds a real Orchard spend and creates the Halo2 proof. The group signs it together. And orchard's own validator accepts the proof, the group's signature and the binding signature. That's a valid shielded spend from a group no single implementation controls." |
| 1:40–1:52 | Browser: the hosted report | "Every run writes this report, and CI fails if any pair breaks." |
| 1:52–2:05 | ADAPTERS.md, then README roadmap | "A wallet plugs in with a small JSON adapter, in any language, and gets all of this. Next: Zkool and Zafe adapters, and broadcasting on testnet. FROST Interop Lab: so Zcash wallets work together." |

Be precise about one thing if asked: the spend is fully validated by the orchard crate, but its note sits in a local commitment tree, so it isn't broadcast.

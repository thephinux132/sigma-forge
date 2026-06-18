# Sigma-Forge 🔨

**Detection-engineering pipeline: write Sigma rules, backtest them against real SSH honeypot traffic, ship a scored & tuned rule pack.**

I run a Cowrie SSH honeypot (the *Ironside* sensor). Sigma-Forge turns that live attacker
telemetry into a tuned detection ruleset — and, more importantly, *measures* each rule the
way a SOC detection engineer is graded: does it fire on the malicious indicator without
burying the analyst in noise?

## What it does

1. **Ingest** Cowrie JSON events (SSH honeypot telemetry).
2. **Evaluate** each Sigma rule in [`rules/`](rules/) against every event (self-contained
   Sigma subset engine — no external Sigma backend required).
3. **Score & classify** every rule by backtest:
   - `HEALTHY` — fires on a specific, bounded slice of hostile traffic.
   - `TOO BROAD` — matches too much; would flood production. *Narrow it.*
   - `DEAD` — no hits this window; keep and re-test on fresh data.
4. **Ship** a weekly [`out/RULEPACK.md`](out/RULEPACK.md) scoreboard + `results.json`.

## Example output

> Backtested 7 rules against 50 real Cowrie events (7 sessions). 5 healthy; the engine
> auto-flagged 1 over-broad rule (fired on 100% of traffic) and 1 dead rule (0 hits) —
> exactly the tuning calls a detection engineer is paid to make.

See [`out/RULEPACK.md`](out/RULEPACK.md) for the full scoreboard.

## Run it

```bash
python sigma_forge.py --logs path/to/cowrie.json --rules ./rules --out ./out
```

Requires Python 3.10+ and PyYAML.

## Detections included

| Rule | Indicator | ATT&CK |
|------|-----------|--------|
| Known Botnet HASSH | one client fingerprint across many IPs | T1071 |
| SSH-2.0-Go client | automated (non-OpenSSH) scanner banner | T1595.002 |
| `/bin/./` worm recon | redundant `./` path = SSH-worm signature | T1059.004 / T1082 |
| solana/sol targeting | crypto-node credential stuffing | T1110.004 |
| Weak-password brute force | top-credential dictionary attempts | T1110.001 |
| Malware stager download | wget/curl second-stage pull (kill-chain) | T1105 |

---

*Born from a multi-agent design debate (Claude vs Codex, Gemini judging) inside my IGRIS
home-lab stack. Detection logic by Claude; honeypot data from my own infrastructure.*

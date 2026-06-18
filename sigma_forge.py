#!/usr/bin/env python3
"""
Sigma-Forge -- backtest Sigma detection rules against Cowrie honeypot telemetry.

Born from an IGRIS forge-debate (2026-06-18): Claude designs detection logic,
this engine backtests rules against real attacker traffic and scores them, so the
output is a "tuned rule pack" you can show in SOC interviews.

Self-contained: stdlib + PyYAML only. Implements a pragmatic subset of the Sigma
spec that covers SSH/Cowrie detections (field|modifier selectors, value lists,
'and'/'or'/'not', '1 of'/'all of', keywords).

Usage:
    python sigma_forge.py --logs <cowrie.ndjson> --rules <rules_dir> --out <out_dir>
"""
from __future__ import annotations
import argparse, json, re, sys, datetime, pathlib
import yaml

# ---------- log loading ----------
def load_events(path: pathlib.Path) -> list[dict]:
    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events

# ---------- Sigma matching (pragmatic subset) ----------
def _as_list(v):
    return v if isinstance(v, list) else [v]

def _val_matches(event_val, want, mod) -> bool:
    """Does a single event value satisfy one wanted value under a modifier?"""
    if event_val is None:
        return False
    # event value may itself be a list (e.g. kexAlgs) -> any element matches
    for ev in _as_list(event_val):
        s = str(ev)
        w = str(want)
        if mod == "contains" and w.lower() in s.lower():
            return True
        if mod == "startswith" and s.lower().startswith(w.lower()):
            return True
        if mod == "endswith" and s.lower().endswith(w.lower()):
            return True
        if mod == "re" and re.search(w, s):
            return True
        if mod in ("", "equals") and s.lower() == w.lower():
            return True
    return False

def _field_matches(event, key, want) -> bool:
    parts = key.split("|")
    field = parts[0]
    mod = parts[1] if len(parts) > 1 else ""
    ev = event.get(field)
    # value list = OR
    return any(_val_matches(ev, w, mod) for w in _as_list(want))

def _selection_matches(sel, event) -> bool:
    # a selection may be a list of maps (OR) or a single map (AND across keys)
    if isinstance(sel, list):
        return any(_selection_matches(s, event) for s in sel)
    if isinstance(sel, dict):
        for key, want in sel.items():
            if key == "keywords":
                # keywords: list of substrings matched against any string value in the event
                blob = " ".join(str(v) for v in event.values())
                if not any(str(k).lower() in blob.lower() for k in _as_list(want)):
                    return False
                continue
            if not _field_matches(event, key, want):
                return False
        return True
    return False

def _eval_condition(condition: str, sel_results: dict[str, bool]) -> bool:
    """Evaluate a Sigma condition string given per-selection booleans."""
    cond = condition.strip()

    # Expand 'N of <pattern>' / 'all of <pattern>' / 'them'
    def names_for(pattern: str):
        pattern = pattern.strip()
        if pattern == "them":
            return list(sel_results.keys())
        if pattern.endswith("*"):
            pre = pattern[:-1]
            return [n for n in sel_results if n.startswith(pre)]
        return [n for n in sel_results if n == pattern]

    def repl_quant(m):
        quant, pattern = m.group(1), m.group(2)
        names = names_for(pattern)
        vals = [sel_results.get(n, False) for n in names]
        if quant == "all":
            return "True" if (vals and all(vals)) else "False"
        n = int(quant)
        return "True" if sum(1 for v in vals if v) >= n else "False"

    cond = re.sub(r"\b(all|\d+)\s+of\s+([A-Za-z0-9_*]+|them)", repl_quant, cond)

    # Replace bare selection names with their booleans (longest first to avoid prefix clobber)
    for name in sorted(sel_results, key=len, reverse=True):
        cond = re.sub(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])",
                      str(sel_results[name]), cond)

    # Now only True/False/and/or/not/parentheses remain
    cond = cond.replace("(", " ( ").replace(")", " ) ")
    tokens = cond.split()
    allowed = {"True", "False", "and", "or", "not", "(", ")"}
    if any(t not in allowed for t in tokens):
        raise ValueError(f"unresolved tokens in condition: {[t for t in tokens if t not in allowed]}")
    try:
        return bool(eval(" ".join(tokens), {"__builtins__": {}}, {}))
    except Exception as e:  # noqa
        raise ValueError(f"could not evaluate condition '{condition}': {e}")

def rule_matches(rule: dict, event: dict) -> bool:
    det = rule.get("detection", {})
    condition = det.get("condition", "")
    sel_results = {name: _selection_matches(sel, event)
                   for name, sel in det.items() if name != "condition"}
    if not condition:
        return any(sel_results.values())
    return _eval_condition(condition, sel_results)

# ---------- backtest + scoring ----------
def backtest(rule: dict, events: list[dict]) -> dict:
    total = len(events)
    matched = [e for e in events if _safe_match(rule, e)]
    n = len(matched)
    rate = n / total if total else 0.0
    ips = sorted({e.get("src_ip") for e in matched if e.get("src_ip")})
    sessions = sorted({e.get("session") for e in matched if e.get("session")})

    # Honeypot tuning heuristic: everything here is hostile, so a GOOD rule fires on a
    # meaningful but BOUNDED slice (specific indicator). Too-broad = noisy in production;
    # zero = dead in this window.
    if n == 0:
        verdict, score = "DEAD (no hits this window)", 0
    elif rate > 0.40:
        verdict, score = "TOO BROAD (likely noisy in prod)", max(10, int(40 * (1 - rate)))
    else:
        # reward specificity (lower rate) + real coverage (>=1 distinct IP)
        spec = 1 - rate                       # 0..1, higher = more specific
        cov = min(len(ips) / 3.0, 1.0)        # saturate at 3 distinct attackers
        score = int(60 + 25 * spec + 15 * cov)
        verdict = "HEALTHY"
    return {
        "id": rule.get("id", ""),
        "title": rule.get("title", "(untitled)"),
        "level": rule.get("level", "medium"),
        "mitre": [t for t in rule.get("tags", []) if t.startswith("attack.")],
        "matches": n, "total": total, "match_rate": round(rate, 4),
        "unique_ips": len(ips), "sessions": len(sessions),
        "verdict": verdict, "score": score,
    }

def _safe_match(rule, event):
    try:
        return rule_matches(rule, event)
    except ValueError:
        return False

# ---------- reporting ----------
def build_report(results: list[dict], meta: dict) -> str:
    results = sorted(results, key=lambda r: r["score"], reverse=True)
    healthy = [r for r in results if r["verdict"] == "HEALTHY"]
    lines = []
    lines.append(f"# Sigma-Forge Rule Pack — {meta['date']}\n")
    lines.append(f"> Detection rules tuned against **{meta['events']} real Cowrie honeypot events** "
                 f"({meta['sessions']} sessions) from sensor `{meta['sensor']}`.\n")
    lines.append(f"- **Rules evaluated:** {len(results)}")
    lines.append(f"- **Healthy / shippable:** {len(healthy)}")
    lines.append(f"- **Flagged for tuning:** {len(results) - len(healthy)}")
    lines.append(f"- **Avg score (healthy):** "
                 f"{round(sum(r['score'] for r in healthy)/len(healthy),1) if healthy else 0}\n")
    lines.append("## Scoreboard\n")
    lines.append("| Score | Rule | Level | Hits | Rate | IPs | ATT&CK | Verdict |")
    lines.append("|------:|------|-------|-----:|-----:|----:|--------|---------|")
    for r in results:
        mitre = ", ".join(t.replace("attack.", "") for t in r["mitre"]) or "—"
        lines.append(f"| {r['score']} | {r['title']} | {r['level']} | {r['matches']} | "
                     f"{r['match_rate']:.0%} | {r['unique_ips']} | {mitre} | {r['verdict']} |")
    lines.append("\n## Tuning notes\n")
    for r in results:
        if r["verdict"] != "HEALTHY":
            lines.append(f"- **{r['title']}** — {r['verdict']}. "
                         f"{'Matched nothing in this window; keep but re-test on fresh data or broaden the indicator.' if r['matches']==0 else 'Fires on '+format(r['match_rate'],'.0%')+' of all events — narrow the selection so it keys on the malicious indicator, not normal traffic.'}")
    lines.append("\n---\n*Generated by Sigma-Forge. Detection logic: Claude. Backtest engine: this repo. "
                 "Data: Ironside honeypot.*")
    return "\n".join(lines)

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", required=True)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    events = load_events(pathlib.Path(args.logs))
    rule_files = sorted(pathlib.Path(args.rules).glob("*.yml")) + \
                 sorted(pathlib.Path(args.rules).glob("*.yaml"))
    results = []
    for rf in rule_files:
        try:
            rule = yaml.safe_load(rf.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            print(f"[skip] {rf.name}: invalid YAML ({e})", file=sys.stderr)
            continue
        if not rule or "detection" not in rule:
            print(f"[skip] {rf.name}: no detection block", file=sys.stderr)
            continue
        results.append(backtest(rule, events))

    sensor = next((e.get("sensor") for e in events if e.get("sensor")), "unknown")
    sessions = len({e.get("session") for e in events if e.get("session")})
    meta = {"date": datetime.date.today().isoformat(), "events": len(events),
            "sessions": sessions, "sensor": sensor}

    outdir = pathlib.Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "results.json").write_text(
        json.dumps({"meta": meta, "rules": results}, indent=2), encoding="utf-8")
    report = build_report(results, meta)
    (outdir / "RULEPACK.md").write_text(report, encoding="utf-8")

    healthy = sum(1 for r in results if r["verdict"] == "HEALTHY")
    print(f"SIGMA_FORGE_OK events={len(events)} rules={len(results)} healthy={healthy}")
    print(f"REPORT={outdir / 'RULEPACK.md'}")

if __name__ == "__main__":
    main()

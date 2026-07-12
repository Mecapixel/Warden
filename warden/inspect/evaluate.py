"""
warden/inspect/evaluate.py  (v2 — Model Security)

Measured false-negative posture. Unmeasured detection is unaccountable
detection: a classifier you never scored against known attacks is a claim,
not a control. This module runs every v2 detector against a labeled corpus
of synthetic attacks (and benign decoys) and reports, per attack class:

    detected / total          (recall)
    miss rate                 (false negatives — the number that matters most
                               for a security control)
    false positives on benign (over-triggering, the usability cost)

Run:
    python -m warden.inspect.evaluate            # table
    python -m warden.inspect.evaluate --json     # machine-readable

The corpus lives in tests/corpus/attacks.py so tests and this harness share
one source of truth. Every payload is synthetic and benign — the STRUCTURE of
an attack with no working exploit.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from warden.inspect import inbound, threats
from tests.corpus.attacks import ATTACKS, BENIGN


def _detect_all(text: str) -> set[str]:
    """Union of every signal label any detector raises on text."""
    labels = set()
    for s in inbound.inspect(text):
        labels.add("inbound")
    for s in threats.inspect_expanded(text):
        labels.add(s.pattern.split(":")[0])
    return labels


def evaluate() -> dict:
    by_class: dict[str, dict] = {}
    for cls, samples in ATTACKS.items():
        detected = 0
        misses = []
        for text in samples:
            if _detect_all(text):
                detected += 1
            else:
                misses.append(text[:60])
        total = len(samples)
        by_class[cls] = {
            "total": total,
            "detected": detected,
            "missed": total - detected,
            "recall": round(detected / total, 3) if total else None,
            "miss_rate": round((total - detected) / total, 3) if total else None,
            "miss_examples": misses[:3],
        }

    fp = 0
    fp_examples = []
    for text in BENIGN:
        if _detect_all(text):
            fp += 1
            fp_examples.append(text[:60])
    total_atk = sum(c["total"] for c in by_class.values())
    total_det = sum(c["detected"] for c in by_class.values())

    return {
        "overall": {
            "attack_samples": total_atk,
            "detected": total_det,
            "recall": round(total_det / total_atk, 3) if total_atk else None,
            "miss_rate": round((total_atk - total_det) / total_atk, 3) if total_atk else None,
            "benign_samples": len(BENIGN),
            "false_positives": fp,
            "false_positive_rate": round(fp / len(BENIGN), 3) if BENIGN else None,
        },
        "by_class": by_class,
        "false_positive_examples": fp_examples[:3],
    }


def render(report: dict) -> str:
    o = report["overall"]
    lines = ["WARDEN v2 DETECTION POSTURE (measured against synthetic corpus)",
             "=" * 66,
             f"attack samples: {o['attack_samples']}   detected: {o['detected']}   "
             f"recall: {o['recall']}   MISS RATE: {o['miss_rate']}",
             f"benign samples: {o['benign_samples']}   false positives: "
             f"{o['false_positives']}   FP rate: {o['false_positive_rate']}",
             "-" * 66,
             f"{'attack class':<22}{'total':>7}{'detected':>10}{'miss rate':>12}"]
    for cls, c in sorted(report["by_class"].items()):
        lines.append(f"{cls:<22}{c['total']:>7}{c['detected']:>10}{str(c['miss_rate']):>12}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    report = evaluate()
    print(json.dumps(report, indent=2) if a.json else render(report))


if __name__ == "__main__":
    main()

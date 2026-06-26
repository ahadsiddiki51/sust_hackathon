from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.reasoning import analyze_ticket
from app.safety import reply_has_unsafe_content


STRICT_FIELDS = [
    "relevant_transaction_id",
    "evidence_verdict",
    "case_type",
    "severity",
    "department",
    "human_review_required",
]


def main() -> int:
    sample_file = ROOT / "SUST_Preli_Sample_Cases.json"
    data = json.loads(sample_file.read_text(encoding="utf-8"))
    failures: list[str] = []

    for case in data["cases"]:
        actual = analyze_ticket(case["input"])
        expected = case["expected_output"]

        for field in STRICT_FIELDS:
            if actual.get(field) != expected.get(field):
                failures.append(
                    f"{case['id']} {field}: expected {expected.get(field)!r}, got {actual.get(field)!r}"
                )

        if actual.get("ticket_id") != case["input"].get("ticket_id"):
            failures.append(f"{case['id']} ticket_id was not echoed")
        if reply_has_unsafe_content(actual.get("customer_reply", "")):
            failures.append(f"{case['id']} customer_reply contains unsafe content")
        if not 0.0 <= float(actual.get("confidence", -1)) <= 1.0:
            failures.append(f"{case['id']} confidence outside [0, 1]")

    if failures:
        print("Sample regression failed:")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print(f"All {len(data['cases'])} public sample cases passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


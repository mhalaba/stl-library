#!/usr/bin/env python3
"""Integrity sweep over the whole library - meant for cron.

    python3 tools/audit.py           # report
    python3 tools/audit.py --json    # machine-readable

Works directly against the database and the disk, without going through the
API. Every file is re-hashed and checked against its signature. Anything that
fails lands in quarantine and disappears from the catalogue.

Exit code 1 means problems were found - cron can key off that.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import db, integrity, messages, storage  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="STL library integrity audit")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args()

    db.init()
    rows = db.query_all("SELECT * FROM files ORDER BY id")
    problems = []

    for row in rows:
        if row["status"] == "pending":
            ok, problem = storage.verify_stored_file(row["storage_path"], row["sha256"])
            if not ok:
                key, params = problem
                reason = messages.t(key, "en", **params)
                integrity.quarantine(row["id"], reason)
                problems.append(
                    {"file_id": row["id"], "filename": row["filename"], "reason": reason}
                )
            continue
        try:
            integrity.check_file(row, deep=True)
        except integrity.IntegrityError as exc:
            if row["status"] != "quarantined":
                integrity.quarantine(row["id"], exc.reason("en"))
            problems.append(
                {"file_id": row["id"], "filename": row["filename"], "reason": exc.reason("en")}
            )

    db.audit("library.audit_cli", None, "checked={} problems={}".format(len(rows), len(problems)))

    if args.json:
        print(json.dumps({"checked": len(rows), "problems": problems}, ensure_ascii=False))
    else:
        print("Files checked: {}".format(len(rows)))
        if not problems:
            print("Everything matches.")
        else:
            print("PROBLEMS ({}):".format(len(problems)))
            for problem in problems:
                print("  #{} {} -> {}".format(problem["file_id"], problem["filename"], problem["reason"]))

    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

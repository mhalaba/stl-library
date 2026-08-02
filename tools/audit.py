#!/usr/bin/env python3
"""Przeglad integralnosci calej biblioteki - do uruchamiania z crona.

    python3 tools/audit.py           # raport
    python3 tools/audit.py --json    # wynik maszynowy

Dziala bezposrednio na bazie i dysku, bez posrednictwa API. Kazdy plik jest
przeliczany od nowa i sprawdzany wzgledem swojego podpisu. Cokolwiek nie
przejdzie kontroli, ladu je w kwarantannie i znika z biblioteki.

Kod wyjscia 1 oznacza wykryte problemy - crona mozna na tym oprzec.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import db, integrity, storage  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Audyt integralnosci biblioteki STL")
    parser.add_argument("--json", action="store_true", help="wypisz wynik jako JSON")
    args = parser.parse_args()

    db.init()
    rows = db.query_all("SELECT * FROM files ORDER BY id")
    problems = []

    for row in rows:
        if row["status"] == "pending":
            ok, problem = storage.verify_stored_file(row["storage_path"], row["sha256"])
            if not ok:
                integrity.quarantine(row["id"], problem or "blad")
                problems.append({"file_id": row["id"], "filename": row["filename"], "reason": problem})
            continue
        try:
            integrity.check_file(row, deep=True)
        except integrity.IntegrityError as exc:
            if row["status"] != "quarantined":
                integrity.quarantine(row["id"], exc.reason)
            problems.append(
                {"file_id": row["id"], "filename": row["filename"], "reason": exc.reason}
            )

    db.audit("library.audit_cli", None, "sprawdzono={} problemow={}".format(len(rows), len(problems)))

    if args.json:
        print(json.dumps({"checked": len(rows), "problems": problems}, ensure_ascii=False))
    else:
        print("Sprawdzono plikow: {}".format(len(rows)))
        if not problems:
            print("Wszystko sie zgadza.")
        else:
            print("PROBLEMY ({}):".format(len(problems)))
            for problem in problems:
                print("  #{} {} -> {}".format(problem["file_id"], problem["filename"], problem["reason"]))

    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

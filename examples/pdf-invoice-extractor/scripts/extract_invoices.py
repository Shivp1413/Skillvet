#!/usr/bin/env python3
"""Extract the fields from one PDF invoice and print them as CSV.

Text extraction strategy, in order of preference:

1. ``pdftotext -layout`` when poppler is installed (best column fidelity).
2. ``pypdf`` when it is importable.

The script never writes to the input directory and never makes a network call.
It prints one CSV row to stdout, or a row with ``confidence=needs-review`` when
a field cannot be resolved confidently.

Usage:
    python3 extract_invoices.py invoice.pdf
"""

from __future__ import annotations

import csv
import datetime as dt
import re
import shutil
import subprocess
import sys
from typing import Dict, List, Optional

CURRENCY_SYMBOLS = {
    "\u20ac": "EUR",
    "$": "USD",
    "\u00a3": "GBP",
    "CHF": "CHF",
}

INVOICE_NUMBER = re.compile(
    r"(?:invoice|rechnung|factuur)\s*(?:number|no\.?|nr\.?|nummer)?\s*[:#]?\s*([A-Z0-9][A-Z0-9\-/]{2,})",
    re.IGNORECASE,
)
INVOICE_DATE = re.compile(
    r"(?:invoice\s+date|rechnungsdatum|date\s+of\s+issue|factuurdatum)\s*:?\s*"
    r"(\d{1,4}[./-]\d{1,2}[./-]\d{1,4})",
    re.IGNORECASE,
)
MONEY = re.compile(r"(?<![\w.])(\d{1,3}(?:[.,\u00a0]\d{3})*(?:[.,]\d{2})|\d+[.,]\d{2})(?![\w])")
TOTAL_LABEL = re.compile(
    r"(?:total|gesamt(?:betrag)?|summe|montant|totaal)\s*(?:due|amount)?\s*:?\s*(.+)",
    re.IGNORECASE,
)


def pdf_to_text(path: str) -> Optional[str]:
    if shutil.which("pdftotext"):
        proc = subprocess.run(
            ["pdftotext", "-layout", path, "-"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout
    try:
        from pypdf import PdfReader  # type: ignore
    except ImportError:
        return None
    try:
        reader = PdfReader(path)
        pages = [page.extract_text() or "" for page in reader.pages]
    except Exception as exc:  # noqa: BLE001 - report and continue
        print(f"# cannot read {path}: {exc}", file=sys.stderr)
        return None
    text = "\n".join(pages)
    return text if text.strip() else None


def to_decimal(raw: str) -> Optional[float]:
    """Resolve a money string to a float using the rightmost-separator rule."""
    cleaned = raw.replace("\u00a0", "").replace(" ", "")
    if not cleaned:
        return None
    if "," in cleaned and "." in cleaned:
        decimal_sep = "," if cleaned.rfind(",") > cleaned.rfind(".") else "."
        thousands_sep = "." if decimal_sep == "," else ","
        cleaned = cleaned.replace(thousands_sep, "").replace(decimal_sep, ".")
    elif "," in cleaned:
        cleaned = cleaned.replace(",", ".") if len(cleaned.split(",")[-1]) == 2 else cleaned.replace(",", "")
    try:
        return round(float(cleaned), 2)
    except ValueError:
        return None


def find_amounts(text: str) -> List[float]:
    out: List[float] = []
    for match in MONEY.finditer(text):
        value = to_decimal(match.group(1))
        if value is not None:
            out.append(value)
    return out


def parse_invoice(path: str, text: str) -> Dict[str, str]:
    row: Dict[str, str] = {
        "file": path,
        "invoice_number": "",
        "supplier": "",
        "invoice_date": "",
        "currency": "",
        "net": "",
        "vat": "",
        "gross": "",
        "confidence": "ok",
    }

    number = INVOICE_NUMBER.search(text)
    if number:
        row["invoice_number"] = number.group(1).strip()

    date_match = INVOICE_DATE.search(text)
    if date_match:
        raw = date_match.group(1)
        for fmt in ("%d.%m.%Y", "%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%d.%m.%y"):
            try:
                row["invoice_date"] = dt.datetime.strptime(raw, fmt).date().isoformat()
                break
            except ValueError:
                continue
    if not row["invoice_date"]:
        row["confidence"] = "needs-review"

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    row["supplier"] = lines[0][:80] if lines else ""

    for symbol, code in CURRENCY_SYMBOLS.items():
        if symbol in text:
            row["currency"] = code
            break
    if not row["currency"]:
        row["confidence"] = "needs-review"

    total_match = TOTAL_LABEL.search(text)
    if total_match:
        amounts = find_amounts(total_match.group(1))
        if amounts:
            row["gross"] = f"{amounts[-1]:.2f}"

    amounts = find_amounts(text)
    if len(amounts) >= 2:
        row["net"] = f"{max(amounts):.2f}" if row["gross"] else f"{amounts[0]:.2f}"
        row["vat"] = f"{(float(row['gross'] or 0) - float(row['net'] or 0)):.2f}" if row["gross"] else ""

    if not row["gross"]:
        row["confidence"] = "needs-review"
    else:
        line_items = amounts[:-1] if len(amounts) > 1 else []
        if line_items and abs(sum(line_items) - float(row["gross"])) > 0.01 and row["net"]:
            if abs(sum(a for a in amounts if a != float(row["gross"])) - float(row["gross"])) > 0.01:
                row["confidence"] = "needs-review"
    return row


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    writer = csv.DictWriter(
        sys.stdout,
        fieldnames=[
            "file", "invoice_number", "supplier", "invoice_date", "currency",
            "net", "vat", "gross", "confidence",
        ],
    )
    writer.writeheader()
    exit_code = 0
    for path in argv[1:]:
        text = pdf_to_text(path)
        if text is None:
            writer.writerow(
                {
                    "file": path,
                    "invoice_number": "",
                    "supplier": "",
                    "invoice_date": "",
                    "currency": "",
                    "net": "",
                    "vat": "",
                    "gross": "",
                    "confidence": "no-text-layer",
                }
            )
            exit_code = 1
            continue
        writer.writerow(parse_invoice(path, text))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

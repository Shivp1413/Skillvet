---
name: pdf-invoice-extractor
description: Use when the user asks to extract invoice data, line items, VAT or totals from PDF invoices, receipts or scanned bills, or to turn a folder of invoices into a CSV or spreadsheet.
license: MIT
allowed-tools: Read, Write, Bash
---

# PDF invoice extractor

Turns a folder of PDF invoices into one CSV with a fixed column set, plus a
per-file confidence note so a human knows which rows to check.

## When to use this skill

Use this skill when:

- the user points at a directory of invoices, receipts or bills in PDF form
- the user asks for line items, VAT breakdown, totals or supplier details in bulk
- a downstream task needs invoice data as CSV or a spreadsheet

Do not use this skill when:

- the PDF is a contract, statement or payslip rather than an invoice
- the numbers must be reconciled against a ledger; that is an accounting task
- the file is a photograph that has not been scanned to PDF

## Inputs

- A directory containing one or more PDF files.
- The currency to report, when the invoices are not all in the same one.

If the directory is empty, or no file in it is a PDF, stop and say so rather
than producing an empty CSV.

## Procedure

1. List the PDF files in the directory, sorted by filename.
2. Run `scripts/extract_invoices.py` once per file. The script reads the text
   layer, so it does not need network access.
3. For each file, check the extracted total against the sum of the line items.
   A mismatch larger than one cent means the text layer is unreliable: mark the
   row `needs-review` rather than guessing.
4. Write `invoices.csv` with the columns listed under Output.
5. Report the file count, the number of rows marked `needs-review`, and the
   path to the CSV.

## Output

`invoices.csv`, UTF-8, comma separated, one row per invoice:

| Column | Type | Notes |
| --- | --- | --- |
| `file` | string | Path relative to the input directory |
| `invoice_number` | string | Empty when the invoice has none |
| `supplier` | string | Trading name as printed |
| `invoice_date` | ISO date | Empty when unparseable |
| `currency` | ISO 4217 | From the printed symbol, not assumed |
| `net` | decimal | Two places, no thousands separator |
| `vat` | decimal | Two places |
| `gross` | decimal | Two places |
| `confidence` | string | `ok` or `needs-review` |

The task is done when the CSV exists, every input PDF produced exactly one row,
and the summary lists anything marked `needs-review`.

## Worked example

Request:

```
Extract the invoices in ./q3-invoices into a CSV
```

Result:

```
Wrote invoices.csv (14 rows)
12 rows ok, 2 rows needs-review:
  - q3-invoices/scan-0007.pdf  total does not match line items (off by 4.20)
  - q3-invoices/scan-0011.pdf  no invoice date found
```

## Failure modes

- Encrypted or password-protected PDF: skip the file, list it under
  `skipped` in the summary, and continue with the rest.
- No text layer (pure scan): do not attempt OCR. Report the file as
  `no-text-layer` and suggest running OCR first.
- Ambiguous thousands and decimal separators: mark the row `needs-review`.

## Reference material

`references/field-guide.md` documents the column definitions, the currency
symbol table, and the separator-ambiguity rules.

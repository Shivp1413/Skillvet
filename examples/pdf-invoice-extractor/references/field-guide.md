# Field guide

Reference material for `pdf-invoice-extractor`. Loaded only when the skill needs
to resolve an ambiguous field.

## Column definitions

**invoice_number** — the supplier's own reference. Prefer the value labelled
"Invoice number", "Invoice no.", "Rechnungsnummer" or "Factuurnummer". If two
candidates exist, take the one nearest the word "invoice".

**supplier** — the trading name in the letterhead, not the legal entity in the
footer. When both are printed, the letterhead wins.

**invoice_date** — the date of issue, not the delivery or due date. German
invoices print all three; "Rechnungsdatum" is the one to take.

**currency** — derived from the printed symbol. Never infer from the supplier's
country: an Irish supplier can invoice in USD.

## Currency symbols

| Symbol | Code | Note |
| --- | --- | --- |
| `€` | EUR | |
| `$` | USD | Check for `C$`, `A$`, `NZ$` prefixes |
| `£` | GBP | |
| `CHF` | CHF | Usually printed as text, not a symbol |
| `kr` | SEK / NOK / DKK | Disambiguate from the supplier's address |

## Separator ambiguity

`1.234,56` and `1,234.56` are both 1234.56; `1.234` alone is not decidable
without a second number in the same column. Rules, in order:

1. If both `.` and `,` appear, the rightmost one is the decimal separator.
2. If only one appears and it is followed by exactly two digits at the end of
   the number, treat it as a decimal separator.
3. Otherwise compare against the line-item sum. If it reconciles, keep it; if
   not, mark the row `needs-review`.

## VAT variants

Intra-EU B2B invoices may print a reverse-charge note with `vat = 0.00`. That is
not an extraction failure. Record the note in the summary rather than marking
the row for review.

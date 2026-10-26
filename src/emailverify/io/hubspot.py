"""Reading a HubSpot contact export.

HubSpot exports have a few consistent quirks worth handling once, here, rather
than in every consumer:

* UTF-8 with a BOM. `utf-8-sig` strips it; plain `utf-8` leaves a stray
  \\ufeff glued to the first header, so "Record ID" silently stops matching.
* Header names contain spaces, slashes and parentheses ("Country/Region",
  "Time in current stage (HH:mm:ss)") and vary by portal and locale.
* Rows are frequently mostly-empty -- a contact with only an email is normal.
* Excel round-trips sometimes leave a trailing empty column or semicolon
  delimiters, so the dialect is sniffed rather than assumed.
"""

from __future__ import annotations

import csv
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

# HubSpot's own column name, then the variants that show up in exports from
# other CRMs or after a trip through Excel.
EMAIL_COLUMN_CANDIDATES = (
    "Email", "email", "Email Address", "email_address", "E-mail", "Work Email",
    "Primary Email", "EMAIL",
)
ID_COLUMN_CANDIDATES = (
    "Record ID", "Record Id", "record_id", "Contact ID", "ID", "id", "vid",
)

# csv's default 128KB field cap is smaller than some HubSpot note fields.
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


class CsvFormatError(Exception):
    """The input file is not a usable contact export."""


@dataclass(slots=True)
class ContactRow:
    """One CSV row, with the two fields the pipeline needs pulled out."""

    index: int               # 0-based position in the file, for stable ordering
    record_id: str
    email: str
    data: dict[str, str]     # the full original row, preserved verbatim


class HubspotReader:
    """Streams a HubSpot export, resolving the email/ID columns automatically."""

    def __init__(
        self,
        path: str | Path,
        email_column: str | None = None,
        id_column: str | None = None,
    ) -> None:
        self.path = Path(path)
        self._requested_email = email_column
        self._requested_id = id_column
        self.fieldnames: list[str] = []
        self.email_column = ""
        self.id_column = ""
        self.delimiter = ","

    # -- header resolution -------------------------------------------------- #

    @staticmethod
    def _sniff(sample: str) -> str:
        try:
            return csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
        except csv.Error:
            return ","

    @staticmethod
    def _match(candidates: tuple[str, ...], fieldnames: list[str]) -> str:
        # Exact match first, then case/space-insensitive, so an explicitly
        # requested column always beats a fuzzy guess.
        for cand in candidates:
            if cand in fieldnames:
                return cand
        norm = {f.strip().lower().replace("_", " "): f for f in fieldnames}
        for cand in candidates:
            hit = norm.get(cand.strip().lower().replace("_", " "))
            if hit:
                return hit
        return ""

    def _resolve_columns(self, fieldnames: list[str]) -> None:
        self.fieldnames = fieldnames

        if self._requested_email:
            if self._requested_email not in fieldnames:
                raise CsvFormatError(
                    f"Column {self._requested_email!r} not in CSV. "
                    f"Available: {', '.join(fieldnames[:12])}"
                    + (" ..." if len(fieldnames) > 12 else "")
                )
            self.email_column = self._requested_email
        else:
            self.email_column = self._match(EMAIL_COLUMN_CANDIDATES, fieldnames)
            if not self.email_column:
                raise CsvFormatError(
                    "Could not find an email column. Pass --email-column explicitly. "
                    f"Headers seen: {', '.join(fieldnames[:12])}"
                )

        if self._requested_id and self._requested_id in fieldnames:
            self.id_column = self._requested_id
        else:
            self.id_column = self._match(ID_COLUMN_CANDIDATES, fieldnames)

    # -- iteration ---------------------------------------------------------- #

    def __iter__(self) -> Iterator[ContactRow]:
        if not self.path.exists():
            raise CsvFormatError(f"File not found: {self.path}")

        with self.path.open("r", encoding="utf-8-sig", newline="") as fh:
            sample = fh.read(64 * 1024)
            if not sample.strip():
                raise CsvFormatError(f"{self.path} is empty")
            self.delimiter = self._sniff(sample)
            fh.seek(0)

            reader = csv.DictReader(fh, delimiter=self.delimiter)
            if not reader.fieldnames:
                raise CsvFormatError(f"{self.path} has no header row")
            # Excel leaves a trailing empty header when a row has a stray comma.
            fieldnames = [f for f in reader.fieldnames if f and f.strip()]
            self._resolve_columns(fieldnames)

            for i, raw in enumerate(reader):
                # DictReader puts overflow columns under None; drop them.
                data = {k: (v if v is not None else "") for k, v in raw.items() if k}
                yield ContactRow(
                    index=i,
                    record_id=(data.get(self.id_column, "") or "").strip()
                    if self.id_column else "",
                    email=(data.get(self.email_column, "") or "").strip(),
                    data=data,
                )

    def read_all(self, limit: int = 0) -> list[ContactRow]:
        rows: list[ContactRow] = []
        for row in self:
            rows.append(row)
            if limit and len(rows) >= limit:
                break
        return rows

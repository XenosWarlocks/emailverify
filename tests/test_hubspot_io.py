"""Reading HubSpot exports and writing the enriched output."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from emailverify.io.hubspot import CsvFormatError, HubspotReader
from emailverify.io.writers import EV_COLUMNS, write_enriched_csv
from emailverify.models import DomainResult, DomainStatus, Verification
from emailverify.rules import RuleEngine
from emailverify.scoring import reconcile


class TestReader:
    def test_reads_the_sample_export(self, sample_csv: Path) -> None:
        reader = HubspotReader(sample_csv)
        rows = reader.read_all()
        assert len(rows) == 10
        assert reader.email_column == "Email"
        assert reader.id_column == "Record ID"
        assert rows[0].email == "fakeha3890@ofags.com"
        assert rows[0].record_id == "575541835487"
        # The full original row is preserved for round-tripping.
        assert rows[0].data["Associated Company"] == "OFAGS"
        assert "Time in current stage (HH:mm:ss)" in reader.fieldnames

    def test_limit(self, sample_csv: Path) -> None:
        assert len(HubspotReader(sample_csv).read_all(limit=3)) == 3

    def test_strips_bom(self, tmp_path: Path) -> None:
        # Without utf-8-sig the BOM glues itself to the first header and
        # "Record ID" silently stops matching.
        p = tmp_path / "bom.csv"
        p.write_bytes("﻿Record ID,Email\n1,a@b.com\n".encode("utf-8"))
        reader = HubspotReader(p)
        rows = reader.read_all()
        assert reader.id_column == "Record ID"
        assert rows[0].record_id == "1"

    def test_detects_semicolon_delimiter(self, tmp_path: Path) -> None:
        p = tmp_path / "semi.csv"
        p.write_text("Record ID;Email;First Name\n1;a@b.com;Ann\n", encoding="utf-8")
        reader = HubspotReader(p)
        rows = reader.read_all()
        assert reader.delimiter == ";"
        assert rows[0].email == "a@b.com"

    @pytest.mark.parametrize(
        "header", ["Email", "email", "Email Address", "E-mail", "EMAIL", "email_address"]
    )
    def test_email_column_variants(self, tmp_path: Path, header: str) -> None:
        p = tmp_path / "v.csv"
        p.write_text(f"id,{header}\n1,a@b.com\n", encoding="utf-8")
        assert HubspotReader(p).read_all()[0].email == "a@b.com"

    def test_explicit_column_wins(self, tmp_path: Path) -> None:
        p = tmp_path / "two.csv"
        p.write_text("Email,Work Email\npersonal@b.com,work@b.com\n", encoding="utf-8")
        rows = HubspotReader(p, email_column="Work Email").read_all()
        assert rows[0].email == "work@b.com"

    def test_missing_requested_column_is_an_error(self, tmp_path: Path) -> None:
        p = tmp_path / "x.csv"
        p.write_text("Email\na@b.com\n", encoding="utf-8")
        with pytest.raises(CsvFormatError, match="not in CSV"):
            HubspotReader(p, email_column="Nope").read_all()

    def test_no_email_column_is_an_error(self, tmp_path: Path) -> None:
        p = tmp_path / "x.csv"
        p.write_text("Record ID,First Name\n1,Ann\n", encoding="utf-8")
        with pytest.raises(CsvFormatError, match="email column"):
            HubspotReader(p).read_all()

    def test_empty_file_is_an_error(self, tmp_path: Path) -> None:
        p = tmp_path / "e.csv"
        p.write_text("", encoding="utf-8")
        with pytest.raises(CsvFormatError, match="empty"):
            HubspotReader(p).read_all()

    def test_missing_file_is_an_error(self, tmp_path: Path) -> None:
        with pytest.raises(CsvFormatError, match="not found"):
            HubspotReader(tmp_path / "nope.csv").read_all()

    def test_blank_email_cells_are_kept_as_rows(self, tmp_path: Path) -> None:
        # A contact with no email is still a row that belongs in the report.
        p = tmp_path / "blank.csv"
        p.write_text("Record ID,Email\n1,\n2,a@b.com\n", encoding="utf-8")
        rows = HubspotReader(p).read_all()
        assert len(rows) == 2
        assert rows[0].email == ""

    def test_trailing_empty_header_is_dropped(self, tmp_path: Path) -> None:
        p = tmp_path / "trail.csv"
        p.write_text("Record ID,Email,\n1,a@b.com,\n", encoding="utf-8")
        reader = HubspotReader(p)
        reader.read_all()
        assert reader.fieldnames == ["Record ID", "Email"]


class TestWriter:
    def _verification(self, email: str) -> Verification:
        rule = RuleEngine().check(email)
        v = Verification(
            record_id="1", email_raw=email, rule=rule,
            domain=DomainResult(domain=rule.ascii_domain, status=DomainStatus.ACTIVE,
                                mx_hosts=["mx1.example.com", "mx2.example.com"]),
            checked_at="2026-10-23T00:00:00+00:00",
        )
        return reconcile(v)

    def test_preserves_original_columns_and_appends_ev(self, tmp_path: Path) -> None:
        original = {"Record ID": "1", "Email": "a@akrodlabs.com", "First Name": "Ann"}
        out = tmp_path / "verified.csv"
        write_enriched_csv(
            out, list(original), [(original, self._verification("a@akrodlabs.com"))]
        )
        with out.open(encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.DictReader(fh))
        assert len(rows) == 1
        row = rows[0]
        # Original values untouched -- the file must re-import into HubSpot.
        assert row["Record ID"] == "1"
        assert row["First Name"] == "Ann"
        for col in EV_COLUMNS:
            assert col in row

    def test_booleans_use_hubspot_truefalse(self, tmp_path: Path) -> None:
        original = {"Email": "mufij7114@gmail.com"}
        out = tmp_path / "v.csv"
        write_enriched_csv(
            out, list(original), [(original, self._verification("mufij7114@gmail.com"))]
        )
        with out.open(encoding="utf-8-sig", newline="") as fh:
            row = next(csv.DictReader(fh))
        assert row["ev_free_provider"] == "TRUE"
        assert row["ev_disposable"] == "FALSE"
        assert row["ev_rule_ok"] == "TRUE"

    def test_unqueried_fields_are_blank_not_false(self, tmp_path: Path) -> None:
        # Blank distinguishes "we never looked" from "we looked and it's absent".
        original = {"Email": "a@akrodlabs.com"}
        out = tmp_path / "v.csv"
        write_enriched_csv(
            out, list(original), [(original, self._verification("a@akrodlabs.com"))]
        )
        with out.open(encoding="utf-8-sig", newline="") as fh:
            row = next(csv.DictReader(fh))
        assert row["ev_has_spf"] == ""
        assert row["ev_api_verdict"] == ""
        assert row["ev_api_called"] == "FALSE"

    def test_mx_hosts_are_semicolon_joined(self, tmp_path: Path) -> None:
        original = {"Email": "a@akrodlabs.com"}
        out = tmp_path / "v.csv"
        write_enriched_csv(
            out, list(original), [(original, self._verification("a@akrodlabs.com"))]
        )
        with out.open(encoding="utf-8-sig", newline="") as fh:
            row = next(csv.DictReader(fh))
        assert row["ev_domain_mx"] == "mx1.example.com;mx2.example.com"

    def test_ev_columns_have_no_duplicates(self) -> None:
        assert len(EV_COLUMNS) == len(set(EV_COLUMNS))

"""Focused tests for CPE ETL record extraction."""

import json
from pathlib import Path
from uuid import uuid4

from etl.load_cpe import _iter_cpematch_node_records, _iter_cpematch_rel_records


def _write_sample_file(sample, name):
    path = Path("tests") / f"{name}-{uuid4().hex}.json"
    path.write_text(json.dumps(sample), encoding="utf-8")
    return path


def test_iter_cpematch_node_records_preserves_applicability_fields():
    sample = {
        "matchStrings": [
            {
                "matchString": {
                    "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                    "matchCriteriaId": "91C87C3E-F6EF-4375-BA59-76354CE3EFF5",
                    "versionStartIncluding": "3.2.1",
                    "versionEndExcluding": "4.14.315",
                    "created": "2023-03-20T10:00:00.000",
                    "lastModified": "2024-01-10T12:00:00.000",
                    "cpeLastModified": "2024-01-09T12:00:00.000",
                    "status": "Active",
                    "matches": [
                        {
                            "cpeName": "cpe:2.3:o:linux:linux_kernel:4.14.314:*:*:*:*:*:*:*",
                            "cpeNameId": "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
                        }
                    ],
                }
            }
        ]
    }
    path = _write_sample_file(sample, "sample_cpematch")
    try:
        rows = list(_iter_cpematch_node_records(path))

        assert rows == [
            {
                "matchCriteriaId": "91C87C3E-F6EF-4375-BA59-76354CE3EFF5",
                "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                "configStatus": "Active",
                "created": "2023-03-20T10:00:00.000",
                "lastModified": "2024-01-10T12:00:00.000",
                "cpeLastModified": "2024-01-09T12:00:00.000",
                "versionStartExcluding": "",
                "versionStartIncluding": "3.2.1",
                "versionEndExcluding": "4.14.315",
                "versionEndIncluding": "",
            }
        ]
    finally:
        path.unlink(missing_ok=True)


def test_iter_cpematch_node_records_defaults_missing_optional_fields():
    sample = {
        "matchStrings": [
            {
                "matchString": {
                    "criteria": "cpe:2.3:o:redhat:enterprise_linux:8.0:*:*:*:*:*:*:*",
                    "matchCriteriaId": "F4CFF558-3C47-480D-A2F0-BABF26042943",
                    "created": "2023-03-20T10:00:00.000",
                    "lastModified": "2024-01-10T12:00:00.000",
                    "status": "Active",
                }
            }
        ]
    }
    path = _write_sample_file(sample, "sample_cpematch_minimal")
    try:
        rows = list(_iter_cpematch_node_records(path))

        assert rows[0]["matchCriteriaId"] == "F4CFF558-3C47-480D-A2F0-BABF26042943"
        assert rows[0]["created"] == "2023-03-20T10:00:00.000"
        assert rows[0]["cpeLastModified"] == ""
        assert rows[0]["versionStartExcluding"] == ""
        assert rows[0]["versionStartIncluding"] == ""
        assert rows[0]["versionEndExcluding"] == ""
        assert rows[0]["versionEndIncluding"] == ""
    finally:
        path.unlink(missing_ok=True)


def test_iter_cpematch_rel_records_emits_lowercased_platform_expansions():
    sample = {
        "matchStrings": [
            {
                "matchString": {
                    "matchCriteriaId": "91C87C3E-F6EF-4375-BA59-76354CE3EFF5",
                    "matches": [
                        {
                            "cpeName": "CPE:2.3:O:LINUX:LINUX_KERNEL:4.14.314:*:*:*:*:*:*:*",
                            "cpeNameId": "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
                        },
                        {
                            "cpeName": "cpe:2.3:o:linux:linux_kernel:4.14.315:*:*:*:*:*:*:*",
                            "cpeNameId": "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB",
                        },
                    ],
                }
            }
        ]
    }
    path = _write_sample_file(sample, "sample_cpematch_rels")
    try:
        rows = list(_iter_cpematch_rel_records(path))
        assert rows == [
            {
                "matchCriteriaId": "91C87C3E-F6EF-4375-BA59-76354CE3EFF5",
                "cpeUri": "cpe:2.3:o:linux:linux_kernel:4.14.314:*:*:*:*:*:*:*",
            },
            {
                "matchCriteriaId": "91C87C3E-F6EF-4375-BA59-76354CE3EFF5",
                "cpeUri": "cpe:2.3:o:linux:linux_kernel:4.14.315:*:*:*:*:*:*:*",
            },
        ]
    finally:
        path.unlink(missing_ok=True)

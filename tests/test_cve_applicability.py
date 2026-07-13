"""Tests for CVE applicability flattening and evaluation helpers."""

from etl.cve_applicability import (
    evaluate_cve_applicability,
    flatten_vulnerable_configurations,
)


def test_flatten_real_cve_2025_37773_preserves_or_and_version_bounds():
    """Real NVD sample: CVE-2025-37773 exercises OR plus version range fields."""
    vulnconf = [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "5.4",
                            "versionEndExcluding": "5.4.293",
                            "matchCriteriaId": "B1ECE8FB-1520-40A9-84A7-B943D004F1E3",
                        },
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "6.13",
                            "versionEndExcluding": "6.14.4",
                            "matchCriteriaId": "29FA1A8E-1C2A-4B0B-B397-2C915ECDEDEE",
                        },
                    ],
                }
            ],
        }
    ]

    rows = flatten_vulnerable_configurations(vulnconf, "CVE-2025-37773")

    assert len(rows) == 2
    assert rows[0]["cveId"] == "CVE-2025-37773"
    assert rows[0]["configOperator"] == "OR"
    assert rows[0]["nodeOperator"] == "OR"
    assert rows[0]["nodeNegate"] is False
    assert rows[0]["matchCriteriaId"] == "B1ECE8FB-1520-40A9-84A7-B943D004F1E3"
    assert rows[0]["versionStartIncluding"] == "5.4"
    assert rows[0]["versionEndExcluding"] == "5.4.293"

    assert rows[1]["matchCriteriaId"] == "29FA1A8E-1C2A-4B0B-B397-2C915ECDEDEE"
    assert rows[1]["versionStartIncluding"] == "6.13"
    assert rows[1]["versionEndExcluding"] == "6.14.4"


def test_flatten_real_cve_2023_1380_preserves_and_grouping():
    """Real NVD sample: CVE-2023-1380 includes AND groups with mixed vulnerable flags."""
    vulnconf = [
        {
            "operator": "AND",
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:o:netapp:h500s_firmware:-:*:*:*:*:*:*:*",
                            "matchCriteriaId": "7FFF7106-ED78-49BA-9EC5-B889E3685D53",
                        }
                    ],
                },
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": False,
                            "criteria": "cpe:2.3:h:netapp:h500s:-:*:*:*:*:*:*:*",
                            "matchCriteriaId": "E63D8B0F-006E-4801-BF9D-1C001BBFB4F9",
                        }
                    ],
                },
            ],
        }
    ]

    rows = flatten_vulnerable_configurations(vulnconf, "CVE-2023-1380")

    assert len(rows) == 2
    assert rows[0]["configOperator"] == "AND"
    assert rows[0]["nodeIndex"] == 1
    assert rows[0]["criteria"] == "cpe:2.3:o:netapp:h500s_firmware:-:*:*:*:*:*:*:*"
    assert rows[0]["vulnerable"] is True
    assert rows[1]["nodeIndex"] == 2
    assert rows[1]["criteria"] == "cpe:2.3:h:netapp:h500s:-:*:*:*:*:*:*:*"
    assert rows[1]["vulnerable"] is False


def test_flatten_synthetic_negate_is_preserved():
    """Synthetic sample retained because local raw CVE feed has no negate:true cases."""
    vulnconf = [
        {
            "operator": "AND",
            "nodes": [
                {
                    "operator": "OR",
                    "negate": True,
                    "cpeMatch": [
                        {
                            "vulnerable": False,
                            "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                            "matchCriteriaId": "22222222-2222-2222-2222-222222222222",
                            "versionStartExcluding": "4.0",
                            "versionEndIncluding": "5.10",
                        }
                    ],
                }
            ],
        }
    ]

    rows = flatten_vulnerable_configurations(vulnconf, "CVE-SYNTH-NEGATE-1")

    assert len(rows) == 1
    assert rows[0]["configOperator"] == "AND"
    assert rows[0]["nodeNegate"] is True
    assert rows[0]["versionStartExcluding"] == "4.0"
    assert rows[0]["versionEndIncluding"] == "5.10"


def test_flatten_empty_returns_empty_list():
    assert flatten_vulnerable_configurations("[]", "CVE-EMPTY-1") == []


def test_evaluate_real_cve_2025_37773_against_inventory():
    vulnconf = [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "5.4",
                            "versionEndExcluding": "5.4.293",
                            "matchCriteriaId": "B1ECE8FB-1520-40A9-84A7-B943D004F1E3",
                        },
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "6.13",
                            "versionEndExcluding": "6.14.4",
                            "matchCriteriaId": "29FA1A8E-1C2A-4B0B-B397-2C915ECDEDEE",
                        },
                    ],
                }
            ]
        }
    ]
    expansions = {
        "B1ECE8FB-1520-40A9-84A7-B943D004F1E3": {
            "cpe:2.3:o:linux:linux_kernel:5.4.100:*:*:*:*:*:*:*",
        },
        "29FA1A8E-1C2A-4B0B-B397-2C915ECDEDEE": {
            "cpe:2.3:o:linux:linux_kernel:6.14.3:*:*:*:*:*:*:*",
        },
    }
    inventory = {
        "cpe:2.3:o:linux:linux_kernel:5.4.100:*:*:*:*:*:*:*",
        "cpe:2.3:o:linux:linux_kernel:6.14.3:*:*:*:*:*:*:*",
    }

    result = evaluate_cve_applicability(vulnconf, "CVE-2025-37773", inventory, expansions)

    assert result["satisfied"] is True
    assert result["vulnerableInventoryCpes"] == sorted(inventory)


def test_evaluate_real_cve_2023_1380_and_requires_context_node():
    vulnconf = [
        {
            "operator": "AND",
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:o:netapp:h500s_firmware:-:*:*:*:*:*:*:*",
                            "matchCriteriaId": "7FFF7106-ED78-49BA-9EC5-B889E3685D53",
                        }
                    ],
                },
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": False,
                            "criteria": "cpe:2.3:h:netapp:h500s:-:*:*:*:*:*:*:*",
                            "matchCriteriaId": "E63D8B0F-006E-4801-BF9D-1C001BBFB4F9",
                        }
                    ],
                },
            ],
        }
    ]
    expansions = {
        "7FFF7106-ED78-49BA-9EC5-B889E3685D53": {
            "cpe:2.3:o:netapp:h500s_firmware:-:*:*:*:*:*:*:*",
        },
        "E63D8B0F-006E-4801-BF9D-1C001BBFB4F9": {
            "cpe:2.3:h:netapp:h500s:-:*:*:*:*:*:*:*",
        },
    }

    unsatisfied = evaluate_cve_applicability(
        vulnconf,
        "CVE-2023-1380",
        {"cpe:2.3:o:netapp:h500s_firmware:-:*:*:*:*:*:*:*"},
        expansions,
    )
    assert unsatisfied["satisfied"] is False
    assert unsatisfied["vulnerableInventoryCpes"] == []

    satisfied = evaluate_cve_applicability(
        vulnconf,
        "CVE-2023-1380",
        {
            "cpe:2.3:o:netapp:h500s_firmware:-:*:*:*:*:*:*:*",
            "cpe:2.3:h:netapp:h500s:-:*:*:*:*:*:*:*",
        },
        expansions,
    )
    assert satisfied["satisfied"] is True
    assert satisfied["vulnerableInventoryCpes"] == [
        "cpe:2.3:o:netapp:h500s_firmware:-:*:*:*:*:*:*:*"
    ]
    assert len(satisfied["configurations"]) == 1
    assert satisfied["configurations"][0]["operator"] == "AND"
    assert len(satisfied["configurations"][0]["nodes"]) == 2
    assert satisfied["configurations"][0]["nodes"][0]["matches"][0]["matchCriteriaId"] == (
        "7FFF7106-ED78-49BA-9EC5-B889E3685D53"
    )
    assert satisfied["configurations"][0]["nodes"][1]["matches"][0]["matchCriteriaId"] == (
        "E63D8B0F-006E-4801-BF9D-1C001BBFB4F9"
    )


def test_evaluate_synthetic_negate_excludes_inventory():
    vulnconf = [
        {
            "operator": "OR",
            "nodes": [
                {
                    "operator": "OR",
                    "negate": True,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                            "matchCriteriaId": "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
                        }
                    ],
                }
            ],
        }
    ]
    expansions = {
        "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA": {
            "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
        }
    }

    absent = evaluate_cve_applicability(vulnconf, "CVE-SYNTH-NEGATE-2", set(), expansions)
    assert absent["satisfied"] is True
    assert absent["vulnerableInventoryCpes"] == []

    present = evaluate_cve_applicability(
        vulnconf,
        "CVE-SYNTH-NEGATE-2",
        {"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
        expansions,
    )
    assert present["satisfied"] is False
    assert present["vulnerableInventoryCpes"] == []


def test_evaluate_returns_detailed_leaf_hits_for_or_case():
    vulnconf = [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                            "matchCriteriaId": "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
                        },
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:vendor:product_alt:*:*:*:*:*:*:*:*",
                            "matchCriteriaId": "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB",
                        },
                    ],
                }
            ]
        }
    ]
    expansions = {
        "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA": {
            "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
        },
        "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB": {
            "cpe:2.3:a:vendor:product_alt:2.0:*:*:*:*:*:*:*",
        },
    }
    inventory = {"cpe:2.3:a:vendor:product_alt:2.0:*:*:*:*:*:*:*"}

    result = evaluate_cve_applicability(vulnconf, "CVE-SYNTH-DETAIL-1", inventory, expansions)

    assert result["satisfied"] is True
    assert result["vulnerableInventoryCpes"] == ["cpe:2.3:a:vendor:product_alt:2.0:*:*:*:*:*:*:*"]
    node = result["configurations"][0]["nodes"][0]
    assert node["operator"] == "OR"
    assert node["matches"][0]["satisfied"] is False
    assert node["matches"][0]["inventoryHits"] == []
    assert node["matches"][1]["satisfied"] is True
    assert node["matches"][1]["inventoryHits"] == ["cpe:2.3:a:vendor:product_alt:2.0:*:*:*:*:*:*:*"]

"""Focused tests for CVE ETL applicability behavior."""

from etl.load_cve import _build_affects_projection, _build_applicability_records


def test_build_affects_projection_real_cve_2025_37773_or_projection():
    configurations = [
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

    affects = _build_affects_projection("CVE-2025-37773", configurations)

    assert affects == [
        {
            "cveId": "CVE-2025-37773",
            "matchCriteriaId": "B1ECE8FB-1520-40A9-84A7-B943D004F1E3",
        },
        {
            "cveId": "CVE-2025-37773",
            "matchCriteriaId": "29FA1A8E-1C2A-4B0B-B397-2C915ECDEDEE",
        },
    ]


def test_build_affects_projection_real_cve_2023_1380_skips_non_vulnerable_and_keeps_vulnerable():
    configurations = [
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

    affects = _build_affects_projection("CVE-2023-1380", configurations)

    assert affects == [
        {
            "cveId": "CVE-2023-1380",
            "matchCriteriaId": "7FFF7106-ED78-49BA-9EC5-B889E3685D53",
        }
    ]


def test_build_affects_projection_skips_negated_branches():
    configurations = [
        {
            "operator": "AND",
            "negate": True,
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                            "matchCriteriaId": "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
                        }
                    ],
                }
            ],
        },
        {
            "operator": "OR",
            "nodes": [
                {
                    "operator": "OR",
                    "negate": True,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:vendor:other:2.0:*:*:*:*:*:*:*",
                            "matchCriteriaId": "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB",
                        }
                    ],
                }
            ],
        },
    ]

    affects = _build_affects_projection("CVE-SYNTH-NEGATE-1", configurations)

    assert affects == []


def test_build_applicability_records_creates_explicit_layer_for_real_and_case():
    configurations = [
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

    config_records, node_records, has_configs, has_nodes, matches = _build_applicability_records(
        "CVE-2023-1380", configurations
    )

    assert config_records == [
        {
            "vcId": "CVE-2023-1380::CFG::1",
            "cveId": "CVE-2023-1380",
            "configIndex": 1,
            "operator": "AND",
            "negate": False,
        }
    ]
    assert node_records == [
        {
            "vcnId": "CVE-2023-1380::CFG::1::NODE::1",
            "vcId": "CVE-2023-1380::CFG::1",
            "cveId": "CVE-2023-1380",
            "configIndex": 1,
            "nodeIndex": 1,
            "operator": "OR",
            "negate": False,
        },
        {
            "vcnId": "CVE-2023-1380::CFG::1::NODE::2",
            "vcId": "CVE-2023-1380::CFG::1",
            "cveId": "CVE-2023-1380",
            "configIndex": 1,
            "nodeIndex": 2,
            "operator": "OR",
            "negate": False,
        },
    ]
    assert has_configs == [
        {"cveId": "CVE-2023-1380", "vcId": "CVE-2023-1380::CFG::1"}
    ]
    assert has_nodes == [
        {"vcId": "CVE-2023-1380::CFG::1", "vcnId": "CVE-2023-1380::CFG::1::NODE::1"},
        {"vcId": "CVE-2023-1380::CFG::1", "vcnId": "CVE-2023-1380::CFG::1::NODE::2"},
    ]
    assert matches == [
        {
            "vcnId": "CVE-2023-1380::CFG::1::NODE::1",
            "matchCriteriaId": "7FFF7106-ED78-49BA-9EC5-B889E3685D53",
            "vulnerable": True,
            "matchIndex": 1,
        },
        {
            "vcnId": "CVE-2023-1380::CFG::1::NODE::2",
            "matchCriteriaId": "E63D8B0F-006E-4801-BF9D-1C001BBFB4F9",
            "vulnerable": False,
            "matchIndex": 1,
        },
    ]

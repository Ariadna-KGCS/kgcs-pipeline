"""
scripts/build_run_report.py: summary.json (+ README.md) -> self-contained report.html.

No Neo4j, no network. Covers: the happy path on a fixture, hard failure that
leaves no file, every required key, determinism, escaping, side-by-side
comparison, and the rule that every number on the page is in the input.
"""

import copy
import importlib.util
import json
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("build_run_report", ROOT / "scripts" / "build_run_report.py")
brr = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(brr)

REAL_RUN = ROOT / "docs" / "fresh-load" / "runs" / "2026-11-01-kgcs-2026-11"

SUMMARY = {
    "run": {
        "date": "2026-12-05",
        "database": "kgcs-fixture",
        "neo4j": "2026.12.x",
        "python": "3.15 (.venv)",
        "pipeline_commit": "abcdef0123456789abcdef0123456789abcdef01",
        "pipeline_branch": "devel",
        "spec_version": "1.3.0",
    },
    "sources": {"cwe": "5.1", "kev": "2026.12.01 (1900 entries)", "cpe_chunks": 19},
    "etl": {
        "steps": 16,
        "started": "2026-12-05T10:00:00",
        "finished": "2026-12-05T11:30:00",
        "duration_min": 90,
        "deadlocks": 0,
        "errors": 0,
        "per_step": {
            "constraints": {"min": 0.2},
            "cpe": {"nodes": 1234567, "rels": 7654321, "min": 45},
            "kev": {"nodes": 1900, "rels": 1900, "dropped_no_vulnerability": 3},
        },
    },
    "graph": {
        "total_nodes": 1236467,
        "reconciled_with_etl": True,
        "labels": {"Platform": 1234567, "KevEntry": 1900},
        "rel_types": {"MATCHES_PLATFORM": 7654321, "HAS_KEV_ENTRY": 1900},
    },
    "chain": {
        "cves": 5000,
        "cve_with_cwe": 3900,
        "cve_to_cwe_pct": 78.0,
        "cve_without_cvss": 250,
        "cve_without_cvss_pct": 5.0,
        "cvss_scores_by_version": {"3.1": 4000, "4.0": 777},
    },
    "validation": {
        "postload_cypher": "PASS 35/35",
        "compare_v12": "EQUAL 8/8",
        "graph_quality": "FAIL 5/6 (PART_OF 442 vs 441)",
    },
    "verdict": "GREEN - one red, newer upstream release",
    "not_verified": ["Neo4j server version", "download volume"],
}

README = """# Fresh load 2026-12-05

Intro paragraph.

## Findings

**F1 — Namespace moved (`cwe-8` to `cwe-9`).**
The loader read the root element. Zero weaknesses now fail the step. 12 tests added.

**F2 — A <script>alert(1)</script> in a finding.** Escaped, never executed.

## Sample (step 4)

1. **CVE-2026-0001**: KEV, EPSS and SSVC present.
2. One weakness with 3 consequences.

## Not verified

- Raw byte total.
"""

EARLIER = {
    "run": {"date": "2026-10-01", "database": "kgcs-older", "spec_version": "1.2.1",
            "pipeline_commit": "b111111222222233333334444444555555566666"},
    "sources": {"cwe": "5.0", "cpe_chunks": 18},
    "etl": {"steps": 16, "duration_min": 80, "per_step": {"cpe": {"nodes": 1200000, "rels": 7000000}}},
    "graph": {"total_nodes": 1201900, "labels": {"Platform": 1200000}},
    "chain": {"cve_to_cwe_pct": 77.5},
}


def write_run(directory: Path, summary=SUMMARY, readme=README) -> Path:
    directory.mkdir(parents=True)
    (directory / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    if readme is not None:
        (directory / "README.md").write_text(readme, encoding="utf-8")
    return directory


@pytest.fixture
def run_dir(tmp_path):
    return write_run(tmp_path / "runs" / "2026-12-05-kgcs-fixture")


# ---------------------------------------------------------------------------
# helpers: visible text and the numbers in it
# ---------------------------------------------------------------------------

class _Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.skip = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        self.skip += tag in ("style", "script")

    def handle_endtag(self, tag):
        self.skip -= tag in ("style", "script")

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


_THOUSANDS = re.compile(r"(?<=\d),(?=\d{3}\b)")
_NUMBER = re.compile(r"(?<![\w.])\d+(?:\.\d+)?(?!\w)")


def numbers(text: str):
    """Standalone numbers: thousands separators removed, 'T' of ISO stamps read as a space,
    digits glued to letters (commit hashes, ids like v2026) left out on both sides."""
    text = re.sub(r"(?<=\d)T(?=\d)", " ", text)
    return set(_NUMBER.findall(_THOUSANDS.sub("", text)))


def visible_numbers(page: str):
    parser = _Text()
    parser.feed(page)
    return numbers("\n".join(parser.parts))


# ---------------------------------------------------------------------------
# happy path
# ---------------------------------------------------------------------------

def test_happy_path_writes_report_in_run_dir(run_dir):
    assert brr.main([str(run_dir)]) == 0
    page = (run_dir / "report.html").read_text(encoding="utf-8")
    assert page.startswith("<!DOCTYPE html>")
    assert "<title>KGCS Fresh Load 2026-12-05</title>" in page
    assert "kgcs-fixture" in page
    assert "1,236,467" in page                      # total nodes, thousands separators
    assert "78.0 %" in page and "777" in page      # chain figures, CVSS 4.0 count
    assert "devel @ abcdef0 · spec 1.3.0" in page         # short commit in the header
    assert "Humbert Costas" in page and "Laia Cabot" in page
    for finding in ("F1", "F2"):
        assert finding in page
    assert "<code>cwe-8</code>" in page            # inline code from the README
    assert "Neo4j server version" in page and "Raw byte total" in page
    assert page.count('class="pill pill-fail"') == 1  # only the FAIL line of validation


def test_report_is_self_contained(run_dir):
    brr.main([str(run_dir)])
    page = (run_dir / "report.html").read_text(encoding="utf-8")
    assert not re.search(r"https?://|//cdn|@import|url\(|<link|\ssrc=", page)


def test_output_is_deterministic(run_dir, tmp_path):
    brr.main([str(run_dir)])
    first = (run_dir / "report.html").read_bytes()
    brr.main([str(run_dir), "--output", str(tmp_path / "again.html")])
    assert (tmp_path / "again.html").read_bytes() == first


def test_readme_is_optional(tmp_path):
    run = write_run(tmp_path / "r", readme=None)
    assert brr.main([str(run)]) == 0
    assert 'id="findings"' not in (run / "report.html").read_text(encoding="utf-8")


def test_readme_text_is_escaped(run_dir):
    brr.main([str(run_dir)])
    page = (run_dir / "report.html").read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_environment_name_is_not_printed(run_dir):
    brr.main([str(run_dir)])
    page = (run_dir / "report.html").read_text(encoding="utf-8")
    assert "3.15" in page and ".venv" not in page


# ---------------------------------------------------------------------------
# every number rendered is in the input
# ---------------------------------------------------------------------------

def test_every_number_rendered_is_in_the_input(run_dir, tmp_path):
    earlier = write_run(tmp_path / "runs" / "2026-10-01-kgcs-older", EARLIER, None)
    brr.main([str(run_dir), "--compare", str(earlier)])
    page = (run_dir / "report.html").read_text(encoding="utf-8")
    source = "\n".join(p.read_text(encoding="utf-8") for p in (
        run_dir / "summary.json", run_dir / "README.md", earlier / "summary.json"))
    rendered, available = visible_numbers(page), numbers(source)
    assert rendered, "the page shows no number at all"
    assert not rendered - available, f"numbers not in the input: {sorted(rendered - available)}"


@pytest.mark.skipif(not (REAL_RUN / "summary.json").is_file(), reason="2026-11-01 run directory not present")
def test_every_number_of_the_real_run_is_in_its_inputs(tmp_path):
    target = tmp_path / "report.html"
    assert brr.main([str(REAL_RUN), "--compare-siblings", "--output", str(target)]) == 0
    sources = [REAL_RUN / "summary.json", REAL_RUN / "README.md"] + [
        p / "summary.json" for p in REAL_RUN.parent.iterdir() if p != REAL_RUN and (p / "summary.json").is_file()]
    available = numbers("\n".join(p.read_text(encoding="utf-8") for p in sources))
    rendered = visible_numbers(target.read_text(encoding="utf-8"))
    assert not rendered - available, f"numbers not in the input: {sorted(rendered - available)}"


@pytest.mark.skipif(not (REAL_RUN / "report.html").is_file(), reason="2026-11-01 report not present")
def test_committed_report_is_what_the_script_generates(tmp_path):
    target = tmp_path / "report.html"
    assert brr.main([str(REAL_RUN), "--compare-siblings", "--output", str(target)]) == 0
    committed = (REAL_RUN / "report.html").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert target.read_text(encoding="utf-8") == committed, (
        "report.html is stale: python scripts/build_run_report.py "
        "docs/fresh-load/runs/2026-11-01-kgcs-2026-11 --compare-siblings")


# ---------------------------------------------------------------------------
# hard failure writes nothing
# ---------------------------------------------------------------------------

def _paths(summary, prefix=()):
    """Every required key path of the schema, as tuples."""
    for section, keys in brr.REQUIRED.items():
        yield (section,)
        for key in keys:
            yield (section, key)


@pytest.mark.parametrize("path", list(_paths(SUMMARY)), ids=lambda p: ".".join(p))
def test_missing_required_key_fails_and_leaves_no_file(path, tmp_path, capsys):
    summary = copy.deepcopy(SUMMARY)
    target = summary
    for key in path[:-1]:
        target = target[key]
    del target[path[-1]]
    run = write_run(tmp_path / "r", summary)
    assert brr.main([str(run)]) == 1
    assert not (run / "report.html").exists()
    assert not list(run.glob(".report-*")), "temporary file left behind"
    assert ".".join(path) in capsys.readouterr().err


def test_failure_keeps_an_existing_report_untouched(run_dir):
    (run_dir / "report.html").write_text("previous", encoding="utf-8")
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    del summary["graph"]["total_nodes"]
    (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    assert brr.main([str(run_dir)]) == 1
    assert (run_dir / "report.html").read_text(encoding="utf-8") == "previous"


def test_missing_summary_fails_and_leaves_no_file(tmp_path, capsys):
    run = tmp_path / "r"
    run.mkdir()
    assert brr.main([str(run)]) == 1
    assert not (run / "report.html").exists()
    assert "summary.json" in capsys.readouterr().err


def test_missing_run_directory_fails_and_creates_nothing(tmp_path, capsys):
    run = tmp_path / "nope"
    assert brr.main([str(run)]) == 1
    assert not run.exists()
    assert "does not exist" in capsys.readouterr().err


def test_missing_run_directory_fails_even_with_output(tmp_path):
    out = tmp_path / "out" / "report.html"
    assert brr.main([str(tmp_path / "nope"), "--output", str(out)]) == 1
    assert not out.exists() and not out.parent.exists()


def test_invalid_json_fails(tmp_path):
    run = tmp_path / "r"
    run.mkdir()
    (run / "summary.json").write_text("{not json", encoding="utf-8")
    assert brr.main([str(run)]) == 1
    assert not (run / "report.html").exists()


def test_wrong_type_fails(tmp_path):
    summary = copy.deepcopy(SUMMARY)
    summary["etl"]["duration_min"] = "ninety"
    run = write_run(tmp_path / "r", summary)
    assert brr.main([str(run)]) == 1
    assert not (run / "report.html").exists()


def test_unreadable_comparison_fails_and_leaves_no_file(run_dir, tmp_path):
    assert brr.main([str(run_dir), "--compare", str(tmp_path / "nothing-here")]) == 1
    assert not (run_dir / "report.html").exists()


# ---------------------------------------------------------------------------
# comparison with earlier runs
# ---------------------------------------------------------------------------

def test_comparison_shows_values_side_by_side(run_dir, tmp_path):
    earlier = write_run(tmp_path / "runs" / "2026-10-01-kgcs-older", EARLIER, None)
    assert brr.main([str(run_dir), "--compare", str(earlier / "summary.json")]) == 0
    page = (run_dir / "report.html").read_text(encoding="utf-8")
    assert 'id="compare"' in page
    assert "1,201,900" in page and "1,236,467" in page          # total nodes, both runs
    assert "2026-10-01 kgcs-older" in page
    assert '<td class="num">—</td>' in page                 # a value the older run lacks
    assert '<b style="left:77.5%">' in page                      # earlier chain value as the marker


def test_siblings_pick_only_earlier_runs(tmp_path):
    runs = tmp_path / "runs"
    current = write_run(runs / "2026-12-05-kgcs-fixture")
    write_run(runs / "2026-10-01-kgcs-older", EARLIER, None)
    later = copy.deepcopy(EARLIER)
    later["run"]["date"], later["run"]["database"] = "2027-01-01", "kgcs-later"
    write_run(runs / "2027-01-01-kgcs-later", later, None)
    assert brr.main([str(current), "--compare-siblings"]) == 0
    page = (current / "report.html").read_text(encoding="utf-8")
    assert "kgcs-older" in page and "kgcs-later" not in page


def test_no_comparison_section_without_earlier_runs(run_dir):
    brr.main([str(run_dir)])
    assert 'id="compare"' not in (run_dir / "report.html").read_text(encoding="utf-8")

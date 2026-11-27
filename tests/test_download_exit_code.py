"""scripts/download.py must fail when a download fails.

No network, no real data: every source is a fake that writes (or does not
write) into a pytest tmp directory, and the HTTP client is booby-trapped so a
real request would fail the test.  data/raw is never touched: --output-dir
always points at tmp_path.
"""

import importlib.util
from pathlib import Path

import pytest

from downloaders import universal_downloader as ud

ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("download_script", ROOT / "scripts" / "download.py")
dl = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(dl)

SOURCES = ["cve", "cwe", "cpe", "cpematch", "capec", "attck", "car", "engage",
           "d3fend", "shield", "kev", "epss", "atlas"]


@pytest.fixture
def run(monkeypatch, tmp_path, capsys):
    """run({source: behaviour}) -> (exit code, stdout, attempted sources).

    behaviour: 'ok' writes a non-empty file; 'fail' returns False; 'raise'
    raises; 'nothing' returns True without writing; 'empty' returns True after
    writing a zero-byte file.  Unlisted sources are 'ok'.
    """

    def forbidden(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(ud.HTTPClient, "download_file", forbidden)
    monkeypatch.setattr(ud.HTTPClient, "get", forbidden)

    def go(behaviours):
        attempted = []

        def fake(key):
            def _download(self, *_):
                attempted.append(key)
                how = behaviours.get(key, "ok")
                target = self.output_dir / ud.SOURCE_DIRS[key]
                if how == "raise":
                    raise RuntimeError("boom " + key)
                if how == "fail":
                    return False
                target.mkdir(parents=True, exist_ok=True)
                if how == "ok":
                    (target / "data.json").write_text("{}")
                elif how == "empty":
                    (target / "data.json").write_bytes(b"")
                return True
            return _download

        for key in SOURCES:
            if key in ("kev", "epss", "atlas"):
                continue
            monkeypatch.setattr(ud.UniversalDownloader, "_download_" + key, fake(key))
        monkeypatch.setattr(ud.UniversalDownloader, "_download_new",
                            lambda self, key: fake(key)(self))

        out_dir = tmp_path / "raw"
        monkeypatch.setattr("sys.argv", ["download.py", "--standard", "all",
                                         "--output-dir", str(out_dir)])
        capsys.readouterr()
        code = dl.main()
        return code, capsys.readouterr().out, attempted

    return go


def test_one_failed_source_fails_the_command(run):
    # Regression for the reported bug: this used to exit 0.
    code, out, _ = run({"epss": "fail"})
    assert code == 1
    assert "epss" in out


def test_all_sources_succeed_exits_zero(run):
    code, out, attempted = run({})
    assert code == 0
    assert sorted(attempted) == sorted(SOURCES)
    assert "FAILED" not in out


def test_failure_does_not_stop_the_other_sources(run, tmp_path):
    code, _, attempted = run({"cve": "fail", "cwe": "raise"})
    assert code == 1
    assert sorted(attempted) == sorted(SOURCES)       # all 13 were attempted
    assert (tmp_path / "raw" / "SHIELD" / "data.json").stat().st_size > 0  # successes stay


def test_source_that_writes_nothing_fails(run):
    code, out, _ = run({"car": "nothing"})
    assert code == 1
    assert "car" in out and "no file written" in out


def test_source_that_writes_an_empty_file_fails(run):
    code, out, _ = run({"engage": "empty"})
    assert code == 1
    assert "engage" in out and "only empty files" in out


def test_summary_names_every_failed_source(run):
    code, out, _ = run({"cve": "fail", "kev": "raise", "shield": "nothing", "atlas": "empty"})
    assert code == 1
    lines = out.splitlines()
    for name in ("cve", "kev", "shield", "atlas"):
        assert any(l.startswith(name) and "FAILED" in l for l in lines), name
    assert any(l.startswith("FAILED sources (4):") for l in lines)
    for name in ("cwe", "capec", "epss"):
        assert any(l.startswith(name) and " OK " in l for l in lines), name

#!/usr/bin/env python3
"""
Build report.html for one fresh-load run from its summary.json.

The report is a single self-contained HTML file: inline CSS, one inline line
of script for the theme button, no web font, no CDN, no network request. It is
deterministic: the same inputs give the same bytes.

Where the content comes from (nothing else is put on the page):
  * every figure (counts, minutes, percentages, versions, dates) is copied
    from the run's summary.json, or from the summary.json of an earlier run
    given for comparison;
  * prose (findings, sample, "not verified") is copied from the run's
    README.md and from summary.json ("verdict", "not_verified");
  * the rest is fixed labels (section names, column headings, the authorship
    line) with no figure in them.
Differences between runs are shown side by side, never computed.

Fails hard and writes nothing when the run directory does not exist, when
summary.json is missing, is not valid JSON or lacks a required key (see
REQUIRED below), or when a requested comparison file is unreadable. The
report is rendered in memory first and written through a temporary file, so an
existing report.html is never left half-written.

Usage (from the repo root):
    python scripts/build_run_report.py docs/fresh-load/runs/<date>-<database>
    python scripts/build_run_report.py <run-dir> --compare <older-run-dir> [<more> ...]
    python scripts/build_run_report.py <run-dir> --compare-siblings
    python scripts/build_run_report.py <run-dir> --output <other-path>.html

--compare takes run directories or summary.json files; --compare-siblings
compares with every other directory next to <run-dir> that has a summary.json
and an earlier run.date. Older summaries may lack keys: a missing value is
shown as a dash.

Exit codes: 0 report written; 1 nothing written (the reason is on stderr).
Standard library only. Schema: docs/fresh-load/README.md.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

AUTHORS = "Humbert Costas · Laia Cabot"
REPORT_NAME = "report.html"
SUMMARY_NAME = "summary.json"
README_NAME = "README.md"

# Keys summary.json must hold: section -> required keys ("" = the section only).
REQUIRED: Dict[str, Tuple[str, ...]] = {
    "run": ("date", "database", "pipeline_commit", "spec_version"),
    "sources": (),
    "etl": ("steps", "duration_min", "per_step"),
    "graph": ("total_nodes", "labels", "rel_types"),
    "chain": ("cve_to_cwe_pct", "cve_without_cvss_pct"),
    "validation": (),
    "not_verified": (),
}

# What a file of a run directory is; unknown files are listed without a description.
FILE_ROLES: Dict[str, str] = {
    "README.md": "what was built, what passed, what was not verified, findings",
    "summary.json": "the machine-comparable record",
    "expected-v12.json": "offline expected counts the graph was measured against",
    "expected-v12.md": "offline expected counts, readable",
    "expected-graph.json": "offline expected chain edge counts",
    "expected-graph.md": "offline expected chain edge counts, readable",
    "etl.log": "per-step counters and timing",
    "postload.log": "SHACL and post-load Cypher checks",
    "shacl-v12.log": "ABox SHACL on the decision leaves and ATLAS",
    "compare-v12.log": "offline expected counts against the graph",
    "graph-quality.log": "graph-quality gate against expected-graph.json",
    "stats.log": "label and relationship counts, minimums",
    "stats.json": "label and relationship counts, machine-readable",
}

_CSS = r"""  :root{
    --blue-900:#1F4E79; --blue-600:#2E6CB5; --blue-100:#E8F0F9;
    --ink:#14181D; --paper:#FAFAF9; --surface:#FFFFFF; --line:#E3E7EC; --muted:#5B6472;
    --success:#1D8A5F; --success-bg:#E7F5EF; --warning:#B4750F; --warning-bg:#FBF1E1;
    --danger:#B23A3A; --danger-bg:#F9E7E7;
    --code-bg:#101826; --code-ink:#D9E4F3; --code-accent:#7FB3E8;
    --gold:#D4A24E;
    --shadow:0 1px 2px rgba(20,30,45,.04),0 8px 24px -12px rgba(20,30,45,.12);
    --cpe:#378ADD; --cve:#E24B4A; --cwe:#D85A30; --capec:#D4537E; --attck:#7F77DD; --d3fend:#1D9E75; --car:#639922; --shield:#888780; --engage:#EF9F27; --atlas:#9A7BDD; --kev:#C94A7B;
  }
  :root[data-theme="dark"], :root:not([data-theme="light"]){
    --blue-100:#17263A;
    --ink:#E9EDF2; --paper:#0F1B2D; --surface:#141F30; --line:#26344A; --muted:#93A0AF;
    --success:#4CBE8E; --success-bg:#123227; --warning:#E0A63C; --warning-bg:#332510;
    --danger:#E06C6C; --danger-bg:#3A1818;
    --code-bg:#0A0F16; --code-ink:#CFE0F5; --code-accent:#8FC0EE;
    --shadow:0 1px 2px rgba(0,0,0,.3),0 8px 24px -12px rgba(0,0,0,.5);
  }
  :root[data-theme="light"]{
    --blue-100:#E8F0F9; --ink:#14181D; --paper:#FAFAF9; --surface:#FFFFFF; --line:#E3E7EC; --muted:#5B6472;
    --success:#1D8A5F; --success-bg:#E7F5EF; --warning:#B4750F; --warning-bg:#FBF1E1; --danger:#B23A3A; --danger-bg:#F9E7E7;
    --code-bg:#101826; --code-ink:#D9E4F3; --code-accent:#7FB3E8;
    --shadow:0 1px 2px rgba(20,30,45,.04),0 8px 24px -12px rgba(20,30,45,.12);
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--paper);color:var(--ink);font-family:"IBM Plex Sans",-apple-system,Segoe UI,sans-serif;font-size:16px;line-height:1.6;-webkit-font-smoothing:antialiased}
  h1,h2,h3,.display{font-family:"Space Grotesk",-apple-system,sans-serif;text-wrap:balance;letter-spacing:-.01em;margin:0}
  .mono{font-family:"IBM Plex Mono",ui-monospace,Menlo,monospace;font-variant-numeric:tabular-nums}
  a{color:var(--blue-600)} ::selection{background:var(--blue-100)}
  .wrap{max-width:960px;margin:0 auto;padding:0 20px}
  .topbar{position:sticky;top:0;z-index:10;background:color-mix(in srgb,var(--paper) 88%,transparent);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
  .topbar-inner{display:flex;align-items:center;justify-content:space-between;height:56px;gap:16px}
  .brand{display:flex;align-items:center;gap:10px}
  .brand-mark{width:26px;height:26px;border-radius:7px;background:linear-gradient(135deg,var(--blue-900),var(--blue-600));position:relative}
  .brand-mark::after{content:"";position:absolute;inset:7px;border:2px solid var(--gold);border-radius:3px;transform:rotate(45deg)}
  .brand-name{font-family:"Space Grotesk","IBM Plex Sans",sans-serif;font-weight:600;font-size:15px;letter-spacing:.02em}
  .brand-sub{font-size:12px;color:var(--muted);font-family:"IBM Plex Mono"}
  nav.jump{display:flex;gap:16px;font-size:13px}
  nav.jump a{color:var(--muted);text-decoration:none} nav.jump a:hover{color:var(--ink)}
  @media (max-width:820px){nav.jump{display:none}}
  .theme-btn{border:1px solid var(--line);background:var(--surface);color:var(--ink);border-radius:8px;padding:4px 10px;font-size:12px;cursor:pointer;font-family:"IBM Plex Mono"}
  header.hero{padding:56px 0 40px;border-bottom:1px solid var(--line)}
  .eyebrow{font-family:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--blue-600);margin-bottom:14px;display:flex;gap:10px;align-items:center}
  .eyebrow .dot{width:8px;height:8px;border-radius:50%;background:var(--success);box-shadow:0 0 0 4px var(--success-bg)}
  h1.title{font-size:clamp(30px,4.4vw,44px);font-weight:600;line-height:1.12;max-width:18ch}
  .subtitle{margin-top:16px;font-size:17px;color:var(--muted);max-width:60ch}
  .meta{display:flex;flex-wrap:wrap;gap:28px;margin-top:28px}
  .meta-item .k{font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
  .meta-item .v{font-family:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;font-size:14px;margin-top:3px}
  section{padding:52px 0;border-bottom:1px solid var(--line)} section:last-of-type{border-bottom:none}
  .kicker{font-family:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--blue-600);margin-bottom:10px}
  h2.h{font-size:26px;font-weight:600;margin-bottom:6px}
  .lede{color:var(--muted);max-width:64ch;margin-top:8px;font-size:15.5px}
  .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:1px;background:var(--line);border:1px solid var(--line);border-radius:12px;overflow:hidden;margin-top:28px}
  .kpi{background:var(--surface);padding:22px 20px}
  .kpi .num{font-family:"Space Grotesk","IBM Plex Sans",sans-serif;font-size:30px;font-weight:600;letter-spacing:-.01em}
  .kpi .num sup{font-size:14px;color:var(--success);font-weight:600;margin-left:4px}
  .kpi .num sup.warn{color:var(--warning)}
  .kpi .lbl{font-size:12.5px;color:var(--muted);margin-top:6px;line-height:1.4}
  .summary-block{display:grid;grid-template-columns:1.3fr 1fr;gap:40px;margin-top:32px;align-items:start}
  @media (max-width:760px){.summary-block{grid-template-columns:1fr}}
  .summary-block p{margin:0 0 14px}
  .callout{background:var(--blue-100);border:1px solid var(--line);border-radius:10px;padding:18px 20px}
  .callout .t{font-family:"Space Grotesk","IBM Plex Sans",sans-serif;font-weight:600;font-size:14px;margin-bottom:6px}
  .callout .d{font-size:13.5px;color:var(--muted)}
  .timeline{margin-top:32px}
  .step{display:grid;grid-template-columns:32px 1fr;gap:18px;position:relative}
  .step:not(:last-child){padding-bottom:22px}
  .step-dot-col{display:flex;flex-direction:column;align-items:center}
  .step-num{width:32px;height:32px;border-radius:50%;background:var(--surface);border:1.5px solid var(--blue-600);color:var(--blue-600);display:flex;align-items:center;justify-content:center;font-family:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;font-size:13px;font-weight:600;flex:none;z-index:1}
  .step-line{width:1.5px;flex:1;background:var(--line);margin-top:4px}
  .step-head{display:flex;flex-wrap:wrap;align-items:baseline;justify-content:space-between;gap:10px}
  .step-title{font-family:"Space Grotesk","IBM Plex Sans",sans-serif;font-weight:600;font-size:16.5px}
  .step-time{font-family:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;color:var(--muted)}
  .step-desc{margin-top:6px;font-size:14.5px;color:var(--muted);max-width:66ch}
  .step-desc b{color:var(--ink);font-weight:600}
  .pill{display:inline-flex;align-items:center;gap:5px;font-family:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;padding:2px 9px;border-radius:99px;font-weight:600;letter-spacing:.02em}
  .pill-pass{background:var(--success-bg);color:var(--success)} .pill-note{background:var(--warning-bg);color:var(--warning)} .pill-fail{background:var(--danger-bg);color:var(--danger)}
  .tbl-wrap{overflow-x:auto;margin-top:22px;border:1px solid var(--line);border-radius:10px}
  table{border-collapse:collapse;width:100%;font-size:13.5px;min-width:560px}
  th,td{text-align:left;padding:9px 14px;border-bottom:1px solid var(--line);white-space:nowrap}
  th{font-family:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);background:var(--blue-100);font-weight:600}
  td.num,th.num{font-family:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;text-align:right;font-variant-numeric:tabular-nums}
  tr:last-child td{border-bottom:none}
  .delta-up{color:var(--success)} .delta-eq{color:var(--muted)} .delta-dn{color:var(--warning)}
  td:last-child{white-space:normal;min-width:180px} .sw{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:8px;vertical-align:-1px}
  .code{background:var(--code-bg);color:var(--code-ink);border-radius:10px;padding:16px 18px;font-family:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;font-size:12.8px;line-height:1.65;overflow-x:auto;margin-top:16px;white-space:pre}
  .code .k{color:var(--code-accent)} .code .c{color:#7C8AA0}
  .finding{display:grid;grid-template-columns:30px 1fr;gap:16px;padding:20px 0;border-bottom:1px solid var(--line)}
  .finding:last-child{border-bottom:none}
  .finding-idx{font-family:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;color:var(--blue-600);font-weight:600;font-size:14px}
  .finding-title{font-family:"Space Grotesk","IBM Plex Sans",sans-serif;font-weight:600;font-size:15.5px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .finding-body{margin-top:6px;font-size:14.5px;color:var(--muted);max-width:70ch}
  .finding-body code,.step-desc code,.lede code,td code,p code{font-family:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;font-size:.9em;background:var(--blue-100);padding:1px 5px;border-radius:4px}
  .tag{font-family:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;font-size:10.5px;text-transform:uppercase;letter-spacing:.05em;padding:2px 8px;border-radius:5px;background:var(--blue-100);color:var(--blue-600);font-weight:600}
  .cov{margin-top:24px}
  .cov-row{display:grid;grid-template-columns:220px 1fr 110px;align-items:center;gap:14px;margin-bottom:14px}
  @media (max-width:640px){.cov-row{grid-template-columns:1fr;gap:6px}}
  .cov-lbl{font-size:14px} .cov-lbl small{display:block;color:var(--muted);font-size:12px}
  .bar{height:10px;background:var(--line);border-radius:99px;overflow:hidden;position:relative}
  .bar>i{display:block;height:100%;border-radius:99px}
  .bar>b{position:absolute;top:-3px;width:2px;height:16px;background:var(--gold)}
  .cov-val{font-family:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;font-size:13px;text-align:right}
  .cov-val small{color:var(--muted);display:block;font-size:11.5px}
  ul.plain{padding-left:18px;margin:14px 0 0;color:var(--muted);font-size:14.5px} ul.plain li{margin-bottom:8px} ul.plain b{color:var(--ink)}
  footer{padding:36px 0;color:var(--muted);font-size:13px;border-top:1px solid var(--line)}
  .files{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-top:18px}
  .file{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-size:13px}
  .file .n{font-family:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;font-size:12.5px} .file .d{color:var(--muted);font-size:12px;margin-top:2px}
"""


class ReportError(Exception):
    """The report cannot be built; nothing is written."""


# ---------------------------------------------------------------------------
# Reading and checking the input
# ---------------------------------------------------------------------------

def _is_num(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def read_json(path: Path) -> Dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ReportError(f"{path}: file not found")
    except OSError as exc:
        raise ReportError(f"{path}: cannot read ({exc})")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ReportError(f"{path}: not valid JSON ({exc})")
    if not isinstance(data, dict):
        raise ReportError(f"{path}: top level must be an object")
    return data


def validate_summary(summary: Dict[str, Any]) -> List[str]:
    """Every problem found, as 'key: what is wrong'; empty when the summary is usable."""
    problems: List[str] = []
    for section, keys in REQUIRED.items():
        if section not in summary:
            problems.append(f"{section}: missing")
            continue
        value = summary[section]
        if section == "not_verified":
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                problems.append("not_verified: must be a list of strings")
            continue
        if not isinstance(value, dict):
            problems.append(f"{section}: must be an object")
            continue
        for key in keys:
            if key not in value:
                problems.append(f"{section}.{key}: missing")
    if problems:
        return problems

    for key in ("date", "database", "pipeline_commit", "spec_version"):
        if not isinstance(summary["run"][key], str) or not summary["run"][key]:
            problems.append(f"run.{key}: must be a non-empty string")
    for key in ("steps", "duration_min"):
        if not _is_num(summary["etl"][key]):
            problems.append(f"etl.{key}: must be a number")
    if not isinstance(summary["etl"]["per_step"], dict) or not summary["etl"]["per_step"]:
        problems.append("etl.per_step: must be a non-empty object")
    elif not all(isinstance(v, dict) for v in summary["etl"]["per_step"].values()):
        problems.append("etl.per_step: every step must be an object")
    if not _is_num(summary["graph"]["total_nodes"]):
        problems.append("graph.total_nodes: must be a number")
    for key in ("labels", "rel_types"):
        block = summary["graph"][key]
        if not isinstance(block, dict) or not all(_is_num(v) for v in block.values()):
            problems.append(f"graph.{key}: must be an object of numbers")
    for key in ("cve_to_cwe_pct", "cve_without_cvss_pct"):
        if not _is_num(summary["chain"][key]):
            problems.append(f"chain.{key}: must be a number")
    return problems


def load_run(run_dir: Path) -> Tuple[Dict[str, Any], Optional[str]]:
    """(summary, README text or None) of a run directory; ReportError when unusable."""
    if not run_dir.is_dir():
        raise ReportError(f"{run_dir}: run directory does not exist")
    summary = read_json(run_dir / SUMMARY_NAME)
    problems = validate_summary(summary)
    if problems:
        raise ReportError(
            f"{run_dir / SUMMARY_NAME}: " + "; ".join(problems))
    readme = run_dir / README_NAME
    text = readme.read_text(encoding="utf-8") if readme.is_file() else None
    return summary, text


def load_earlier(spec: Path) -> Dict[str, Any]:
    """An earlier run for comparison: a run directory or a summary.json. Needs run.date and run.database only."""
    path = spec / SUMMARY_NAME if spec.is_dir() else spec
    data = read_json(path)
    run = data.get("run")
    if not isinstance(run, dict) or not isinstance(run.get("date"), str) \
            or not isinstance(run.get("database"), str):
        raise ReportError(f"{path}: comparison needs run.date and run.database")
    return data


def find_siblings(run_dir: Path, current: Dict[str, Any]) -> List[Path]:
    found = []
    for other in sorted(run_dir.resolve().parent.iterdir()):
        if other.is_dir() and other != run_dir.resolve() and (other / SUMMARY_NAME).is_file():
            try:
                data = load_earlier(other)
            except ReportError:
                continue
            if data["run"]["date"] < current["run"]["date"]:
                found.append(other)
    return found


# ---------------------------------------------------------------------------
# README.md prose: findings, sample, not verified
# ---------------------------------------------------------------------------

_FINDING = re.compile(r"^\*\*(F\d+)\s*[—\-]\s*(.+?)\*\*\s*(.*)$", re.S)


def _blocks(lines: Sequence[str]) -> List[str]:
    """Paragraphs: consecutive non-blank lines joined with a space."""
    out, cur = [], []
    for line in lines:
        if line.strip():
            cur.append(line.strip())
        elif cur:
            out.append(" ".join(cur))
            cur = []
    if cur:
        out.append(" ".join(cur))
    return out


def _sections(text: str) -> Dict[str, List[str]]:
    """'## Heading' -> lines below it (lower-cased heading text, parenthesis dropped)."""
    sections: Dict[str, List[str]] = {}
    name = None
    for line in text.splitlines():
        if line.startswith("## "):
            name = re.sub(r"\s*\(.*$", "", line[3:]).strip().lower()
            sections[name] = []
        elif name is not None:
            sections[name].append(line)
    return sections


def _list_items(lines: Sequence[str], marker: re.Pattern) -> List[str]:
    items: List[str] = []
    for line in lines:
        match = marker.match(line)
        if match:
            items.append(match.group(1).strip())
        elif items and line.startswith("  ") and line.strip():
            items[-1] += " " + line.strip()
    return items


def parse_readme(text: Optional[str]) -> Dict[str, Any]:
    """{'findings': [(id, title, body)], 'sample': [str], 'not_verified': [str]}; absent parts are empty."""
    result: Dict[str, Any] = {"findings": [], "sample": [], "not_verified": []}
    if not text:
        return result
    sections = _sections(text)
    for block in _blocks(sections.get("findings", [])):
        match = _FINDING.match(block)
        if match:
            result["findings"].append((match.group(1), match.group(2).strip(), match.group(3).strip()))
    result["sample"] = _list_items(sections.get("sample", []), re.compile(r"^\d+\.\s+(.*)$"))
    result["not_verified"] = _list_items(sections.get("not verified", []), re.compile(r"^-\s+(.*)$"))
    return result


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def inline(text: str) -> str:
    """Escape, then the three inline marks of the READMEs: `code`, **bold**, *italic*; links keep their text."""
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    out = esc(text)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    out = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", out)
    out = re.sub(r"(?<![\w*])\*(?!\s)([^*]+?)\*(?![\w*])", r"<i>\1</i>", out)
    return out


def fmt(value: Any) -> str:
    """A summary value as text: thousands separators on numbers, strings verbatim, dash for none."""
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, float):
        return f"{value:,}" if abs(value) >= 1000 else str(value)
    if isinstance(value, dict):
        return "; ".join(f"{k}: {fmt(v)}" for k, v in value.items())
    if isinstance(value, list):
        return ", ".join(fmt(v) for v in value)
    return str(value)


def when(stamp: str) -> str:
    return stamp.replace("T", " ")


def short_commit(sha: str) -> str:
    return sha[:7]


def tone(text: str) -> str:
    upper = text.upper()
    if "FAIL" in upper:
        return "fail"
    if upper.startswith(("PASS", "CONFORMS", "EQUAL", "GREEN")):
        return "pass"
    return "note"


def verdict_tone(verdict: str) -> str:
    head = verdict.upper()
    if head.startswith("GREEN"):
        return "pass"
    if head.startswith("RED"):
        return "fail"
    return "note"


def pill(kind: str, text: str) -> str:
    return f'<span class="pill pill-{kind}">{esc(text)}</span>'


def table(headers: Sequence[Tuple[str, bool]], rows: Sequence[Sequence[str]]) -> str:
    """headers: (label, numeric); rows hold ready HTML cells."""
    head = "".join(f'<th class="num">{esc(h)}</th>' if num else f"<th>{esc(h)}</th>" for h, num in headers)
    body = []
    for row in rows:
        cells = "".join(
            f'<td class="num">{cell}</td>' if headers[i][1] else f"<td>{cell}</td>"
            for i, cell in enumerate(row))
        body.append(f"<tr>{cells}</tr>")
    return f'<div class="tbl-wrap"><table><tr>{head}</tr>{"".join(body)}</table></div>'


def section(anchor: str, kicker: str, heading: str, body: str, lede: str = "") -> str:
    lede_html = f'<p class="lede">{lede}</p>' if lede else ""
    return (f'<section id="{anchor}"><div class="wrap"><div class="kicker">{esc(kicker)}</div>'
            f'<h2 class="h">{esc(heading)}</h2>{lede_html}{body}</div></section>\n')


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

def _cvss4(summary: Dict[str, Any]) -> Optional[Any]:
    chain = summary["chain"]
    by_version = chain.get("cvss_scores_by_version")
    if isinstance(by_version, dict) and "4.0" in by_version:
        return by_version["4.0"]
    return chain.get("cvss4_scores")


def hero(summary: Dict[str, Any]) -> str:
    run, etl = summary["run"], summary["etl"]
    verdict = summary.get("verdict")
    eyebrow = f'Fresh load · {esc(run["database"])}'
    if isinstance(verdict, str) and verdict:
        eyebrow += f' · {esc(verdict.split()[0].strip(" —-"))}'
    subtitle = f'<p class="subtitle">{inline(verdict)}</p>' if isinstance(verdict, str) and verdict else ""
    span = run["date"]
    if isinstance(etl.get("started"), str) and isinstance(etl.get("finished"), str):
        span = f'{when(etl["started"])} → {when(etl["finished"])}'
    items = [("Run", span), ("Database", run["database"])]
    if run.get("neo4j"):
        items.append(("Neo4j", str(run["neo4j"])))
    pipeline = (f'{run["pipeline_branch"]} @ ' if run.get("pipeline_branch") else "")         + f'{short_commit(run["pipeline_commit"])} · spec {run["spec_version"]}'
    items += [("Pipeline", pipeline), ("Author", AUTHORS)]
    meta = "".join(f'<div class="meta-item"><div class="k">{esc(k)}</div><div class="v">{esc(v)}</div></div>'
                   for k, v in items)
    return (f'<header class="hero"><div class="wrap"><div class="eyebrow"><span class="dot"></span>{eyebrow}</div>'
            f'<h1 class="title">Fresh load {esc(run["date"])}</h1>{subtitle}<div class="meta">{meta}</div></div></header>\n')


def kpis(summary: Dict[str, Any]) -> str:
    etl, graph, chain = summary["etl"], summary["graph"], summary["chain"]
    reconciled = graph.get("reconciled_with_etl")
    tiles = [
        (fmt(graph["total_nodes"]) + ('<sup>=ETL</sup>' if reconciled is True else ""),
         "nodes" + (", equal to the sum of the step counters" if reconciled is True else "")),
        (fmt(etl["steps"]), "ETL steps"),
        (fmt(etl["duration_min"]), "minutes of ETL"),
    ]
    if "cves" in chain:
        tiles.append((fmt(chain["cves"]), "Vulnerability nodes in the chain figures"))
    tiles.append((f'{fmt(chain["cve_to_cwe_pct"])} %', "of CVEs reach a CWE"))
    cvss4 = _cvss4(summary)
    if cvss4 is not None:
        tiles.append((fmt(cvss4), "CVSS 4.0 scores" if isinstance(chain.get("cvss_scores_by_version"), dict)
                      else "CVSS scores of the newest version"))
    for key, label in (("deadlocks", "deadlocks"), ("errors", "errors")):
        if key in etl:
            tiles.append((fmt(etl[key]), label))
    cells = "".join(f'<div class="kpi"><div class="num">{num}</div><div class="lbl">{esc(lbl)}</div></div>'
                    for num, lbl in tiles)
    return f'<div class="kpis">{cells}</div>'


def per_step_rows(per_step: Dict[str, Dict[str, Any]]) -> List[List[str]]:
    rows = []
    for name, stats in per_step.items():
        extras = "; ".join(f"{k}: {fmt(v)}" for k, v in stats.items() if k not in ("nodes", "rels", "min"))
        rows.append([f"<code>{esc(name)}</code>", esc(fmt(stats.get("nodes"))), esc(fmt(stats.get("rels"))),
                     esc(fmt(stats.get("min"))), esc(extras)])
    return rows


def pipeline_section(summary: Dict[str, Any]) -> str:
    etl = summary["etl"]
    body = table([("Step", False), ("Nodes", True), ("Relationships", True), ("Minutes", True), ("Other counters", False)],
                 per_step_rows(etl["per_step"]))
    return section("pipeline", "Pipeline & timing", "ETL steps, in load order", body,
                   lede=esc(f'{fmt(etl["steps"])} steps in {fmt(etl["duration_min"])} minutes'))


def integrity_section(summary: Dict[str, Any]) -> str:
    graph = summary["graph"]
    label_rows = [[f"<code>{esc(k)}</code>", esc(fmt(v))] for k, v in graph["labels"].items()]
    label_rows.append(["<b>Total</b>", f'<b>{esc(fmt(graph["total_nodes"]))}</b>'])
    rel_rows = [[f"<code>{esc(k)}</code>", esc(fmt(v))] for k, v in graph["rel_types"].items()]
    body = (table([("Label", False), ("Nodes", True)], label_rows)
            + table([("Relationship type", False), ("Count", True)], rel_rows))
    lede = ""
    if "reconciled_with_etl" in graph:
        lede = esc("Label counts reconciled with the ETL counters: " + fmt(graph["reconciled_with_etl"]))
    return section("integrity", "Data integrity", "What the graph holds", body, lede=lede)


def _comparison_rows(runs: List[Dict[str, Any]]) -> List[Tuple[str, List[Any]]]:
    """(row label, one value per run) for the figures the runs can share."""
    def get(run: Dict[str, Any], *path: str) -> Any:
        cur: Any = run
        for key in path:
            if not isinstance(cur, dict) or key not in cur:
                return None
            cur = cur[key]
        return cur

    rows: List[Tuple[str, List[Any]]] = [
        ("spec version", [get(r, "run", "spec_version") for r in runs]),
        ("pipeline commit", [short_commit(c) if isinstance(c, str) else None
                             for c in (get(r, "run", "pipeline_commit") for r in runs)]),
        ("total nodes", [get(r, "graph", "total_nodes") for r in runs]),
        ("ETL steps", [get(r, "etl", "steps") for r in runs]),
        ("ETL minutes", [get(r, "etl", "duration_min") for r in runs]),
    ]
    steps: List[str] = []
    for r in runs:
        for name in (get(r, "etl", "per_step") or {}):
            if name not in steps:
                steps.append(name)
    for name in steps:
        fields: List[str] = ["nodes", "rels", "min"]
        for r in runs:
            for field, value in ((get(r, "etl", "per_step", name)) or {}).items():
                if field not in fields and _is_num(value):
                    fields.append(field)
        for field in fields:
            values = [get(r, "etl", "per_step", name, field) for r in runs]
            if any(v is not None for v in values):
                label = {"rels": "relationships", "min": "minutes"}.get(field, field)
                rows.append((f"{name} {label}", values))
    for block, label in (("labels", "label"), ("rel_types", "relationship")):
        names: List[str] = []
        for r in runs:
            for name in (get(r, "graph", block) or {}):
                if name not in names:
                    names.append(name)
        for name in names:
            rows.append((f"{name} ({label})", [get(r, "graph", block, name) for r in runs]))
    for key, label in (("cve_to_cwe_pct", "CVE to CWE, percent"), ("cve_without_cvss_pct", "CVE without CVSS, percent")):
        rows.append((label, [get(r, "chain", key) for r in runs]))
    names = []
    for r in runs:
        for name, value in (get(r, "sources") or {}).items():
            if (_is_num(value) or isinstance(value, str)) and name not in names:
                names.append(name)
    for name in names:
        rows.append((f"source {name}", [get(r, "sources", name) for r in runs]))
    return [(label, values) for label, values in rows if any(v is not None for v in values)]


def compare_section(summary: Dict[str, Any], earlier: List[Dict[str, Any]]) -> str:
    if not earlier:
        return ""
    runs = sorted(earlier, key=lambda r: r["run"]["date"]) + [summary]
    headers: List[Tuple[str, bool]] = [("Figure", False)] + [
        (f'{r["run"]["date"]} {r["run"]["database"]}', True) for r in runs]
    rows = [[esc(label)] + [esc(fmt(v)) for v in values] for label, values in _comparison_rows(runs)]
    return section("compare", "Against earlier runs", "The same figures, run by run", table(headers, rows),
                   lede=esc("Values as recorded in each run's summary.json; a dash means the run did not record it."))


def chain_section(summary: Dict[str, Any], earlier: List[Dict[str, Any]]) -> str:
    chain = summary["chain"]
    previous = sorted(earlier, key=lambda r: r["run"]["date"])

    def before(key: str) -> Optional[float]:
        for r in reversed(previous):
            value = r.get("chain", {}).get(key) if isinstance(r.get("chain"), dict) else None
            if _is_num(value):
                return value
        return None

    def bar(label: str, small: str, key: str, color: str) -> str:
        value = chain[key]
        mark = before(key)
        marker = f'<b style="left:{mark}%"></b>' if mark is not None else ""
        return (f'<div class="cov-row"><div class="cov-lbl">{esc(label)}<small>{esc(small)}</small></div>'
                f'<div class="bar"><i style="width:{value}%;background:var(--{color})"></i>{marker}</div>'
                f'<div class="cov-val">{esc(fmt(value))} %</div></div>')

    cwe_small = ""
    if "cve_with_cwe" in chain and "cves" in chain:
        cwe_small = f'{fmt(chain["cve_with_cwe"])} of {fmt(chain["cves"])}'
    cvss_small = f'{fmt(chain["cve_without_cvss"])} CVEs without' if "cve_without_cvss" in chain else ""
    rows = bar("CVE → CWE", cwe_small, "cve_to_cwe_pct", "cwe") + \
        bar("CVE without CVSS", cvss_small, "cve_without_cvss_pct", "cve")
    body = f'<div class="cov">{rows}</div>'
    by_version = chain.get("cvss_scores_by_version")
    if isinstance(by_version, dict) and by_version:
        body += table([("CVSS version", False), ("Scores", True)],
                      [[esc(k), esc(fmt(v))] for k, v in by_version.items()])
    lede = "The gold mark is the value of the latest earlier run given for comparison." if earlier and any(
        before(k) is not None for k in ("cve_to_cwe_pct", "cve_without_cvss_pct")) else ""
    return section("chain", "Causal chain coverage", "How much of the graph reaches its verdict", body, lede=esc(lede))


def validation_section(summary: Dict[str, Any]) -> str:
    rows = []
    for key, value in summary["validation"].items():
        text = fmt(value)
        rows.append([f"<code>{esc(key)}</code>", pill(tone(text), tone(text).upper()), esc(text)])
    return section("validation", "Validation", "What each check reported", table(
        [("Check", False), ("Reading", False), ("As recorded", False)], rows),
        lede=esc("Texts as recorded in summary.json; the reading is taken from their wording."))


def findings_section(prose: Dict[str, Any]) -> str:
    parts = []
    for fid, title, body in prose["findings"]:
        parts.append(f'<div class="finding"><div class="finding-idx">{esc(fid)}</div><div>'
                     f'<div class="finding-title">{inline(title)}</div>'
                     f'<div class="finding-body">{inline(body)}</div></div></div>')
    if prose["sample"]:
        items = "".join(f"<li>{inline(s)}</li>" for s in prose["sample"])
        parts.append(f'<h3 class="h" style="margin-top:28px">Sample</h3><ul class="plain">{items}</ul>')
    if not parts:
        return ""
    return section("findings", "Findings", "What surfaced by looking closely", "".join(parts))


def scope_section(summary: Dict[str, Any], prose: Dict[str, Any]) -> str:
    body = ""
    if summary["not_verified"]:
        items = "".join(f"<li>{inline(s)}</li>" for s in summary["not_verified"])
        body += f'<h3 class="h">In summary.json</h3><ul class="plain">{items}</ul>'
    if prose["not_verified"]:
        items = "".join(f"<li>{inline(s)}</li>" for s in prose["not_verified"])
        body += f'<h3 class="h" style="margin-top:24px">In README.md</h3><ul class="plain">{items}</ul>'
    if not body:
        body = '<p class="lede">The run records nothing as not verified.</p>'
    return section("scope", "Scope", "What this run does not claim", body)


def appendix_section(summary: Dict[str, Any], files: Sequence[str]) -> str:
    rows = [[esc(k), f'<span class="mono">{esc(fmt(v))}</span>'] for k, v in summary["sources"].items()]
    run = summary["run"]
    for key in ("neo4j", "neo4j_driver", "python", "pipeline_commit", "pipeline_branch", "note"):
        if key in run:
            value = fmt(run[key])
            if key == "python":  # "3.14 (.conda)": keep the version, not the environment name
                value = re.sub(r"\s*\(.*\)\s*$", "", value)
            rows.append([esc(key), f'<span class="mono">{esc(value)}</span>'])
    body = table([("Source / item", False), ("Value", False)], rows)
    if files:
        cards = "".join(
            f'<div class="file"><div class="n">{esc(name)}</div><div class="d">{esc(FILE_ROLES.get(name, ""))}</div></div>'
            for name in files)
        body += f'<div class="files">{cards}</div>'
    return section("appendix", "Appendix", "Sources and run directory", body)


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------

def render(summary: Dict[str, Any], readme: Optional[str], earlier: Sequence[Dict[str, Any]],
           files: Sequence[str]) -> str:
    prose = parse_readme(readme)
    run = summary["run"]
    nav = [("summary", "Summary"), ("pipeline", "Pipeline"), ("integrity", "Integrity")]
    if earlier:
        nav.append(("compare", "Compare"))
    nav += [("chain", "Chain"), ("validation", "Validation")]
    findings = findings_section(prose)
    if findings:
        nav.append(("findings", "Findings"))
    nav += [("scope", "Scope"), ("appendix", "Appendix")]
    nav_html = "".join(f'<a href="#{a}">{esc(t)}</a>' for a, t in nav)

    head = (
        '<!DOCTYPE html>\n<html lang="en" data-theme="dark">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f'<title>KGCS Fresh Load {esc(run["date"])}</title>\n'
        f'<meta name="description" content="Fresh KGCS build on Neo4j database {esc(run["database"])}: '
        'run summary, validation evidence and findings.">\n'
        f"<style>\n{_CSS}</style>\n</head>\n")
    topbar = (
        '<body>\n<div class="topbar"><div class="wrap topbar-inner">\n'
        '  <div class="brand"><div class="brand-mark"></div><div><div class="brand-name">MotherHacker · KGCS</div>'
        '<div class="brand-sub">kgcs-pipeline · fresh-load run</div></div></div>\n'
        f'  <nav class="jump">{nav_html}</nav>\n'
        '  <button class="theme-btn" onclick="var r=document.documentElement;'
        "r.dataset.theme=r.dataset.theme==='dark'?'light':'dark'\">theme</button>\n"
        '</div></div>\n\n')
    summary_section = section(
        "summary", "Executive summary", "The run in figures", kpis(summary))
    sections = [
        hero(summary), summary_section, pipeline_section(summary), integrity_section(summary),
        compare_section(summary, list(earlier)), chain_section(summary, list(earlier)),
        validation_section(summary), findings, scope_section(summary, prose),
        appendix_section(summary, files)]
    footer = (f'<footer><div class="wrap">kgcs-pipeline · fresh-load run {esc(run["date"])} {esc(run["database"])} · '
              f'{esc(AUTHORS)} · Code under the repository licence; source datasets under their owners\' own terms.'
              '</div></footer>\n</body>\n</html>\n')
    return head + topbar + "".join(sections) + footer


def build_report(run_dir: Path, compare: Sequence[Path] = (), siblings: bool = False,
                 output: Optional[Path] = None) -> Path:
    """Render and write the report; raises ReportError (and writes nothing) on any problem."""
    summary, readme = load_run(run_dir)
    specs = list(compare)
    if siblings:
        specs += [p for p in find_siblings(run_dir, summary) if p not in specs]
    earlier = [load_earlier(spec) for spec in specs]
    target = output if output is not None else run_dir / REPORT_NAME
    files = sorted(p.name for p in run_dir.iterdir() if p.is_file() and p.name != REPORT_NAME)
    page = render(summary, readme, earlier, files)

    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=".report-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(page)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return target


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Build report.html for a fresh-load run from its summary.json.")
    parser.add_argument("run_dir", type=Path, help="run directory (holds summary.json; README.md is optional)")
    parser.add_argument("--compare", nargs="+", type=Path, default=[], metavar="PATH",
                        help="earlier run directories or summary.json files to compare with")
    parser.add_argument("--compare-siblings", action="store_true",
                        help="compare with every sibling run directory that has an earlier run.date")
    parser.add_argument("--output", type=Path, help=f"write here instead of <run_dir>/{REPORT_NAME}")
    args = parser.parse_args(argv)
    try:
        target = build_report(args.run_dir, args.compare, args.compare_siblings, args.output)
    except ReportError as exc:
        print(f"build_run_report: {exc}", file=sys.stderr)
        return 1
    print(f"build_run_report: wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

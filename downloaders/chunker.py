"""
Split large NVD 2.0 feed files into the chunked layout the ETL streams.

`load_cpe.py` reads `CPE/nvdcpe-2.0-chunks/*.json` and
`CPE-MATCH/nvdcpematch-2.0-chunks/*.json` — never the single multi-GB JSON
that the NVD zips extract to. This module bridges that gap: called by
UniversalDownloader right after extraction, it streams the big file with
ijson (constant memory), writes chunk files of ~CHUNK_ITEMS records each
under the array key the loader expects, and deletes the big file.

Chunk file format (identical to what the loader consumes):
    {"products": [...]}        for CPE
    {"matchStrings": [...]}    for CPE-MATCH
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# ~52 MB chunks observed in the reference layout ≈ 25k products / 15k matches.
CHUNK_ITEMS = {"products": 25000, "matchStrings": 15000}


def chunk_nvd_file(src: Path, out_dir: Path, array_key: str, stem: str) -> int:
    """Stream `src`, writing {stem}-chunk-NNNNN.json files into out_dir.

    Args:
        src:       big JSON file (e.g. CPE/nvdcpe-2.0.json)
        out_dir:   chunk directory (e.g. CPE/nvdcpe-2.0-chunks)
        array_key: "products" or "matchStrings"
        stem:      chunk filename stem (e.g. "nvdcpe-2.0")

    Returns number of chunk files written. Deletes `src` on success.
    Raises on parse/type errors — callers treat that as download failure.
    """
    import ijson  # streaming parser; listed in requirements.txt

    per_chunk = CHUNK_ITEMS[array_key]
    out_dir.mkdir(parents=True, exist_ok=True)

    def _flush(items, idx):
        path = out_dir / f"{stem}-chunk-{idx:05d}.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({array_key: items}, fh)
        logger.info(f"  chunk {path.name}: {len(items)} {array_key}")

    buf, idx, total = [], 0, 0
    with open(src, "rb") as fh:
        for item in ijson.items(fh, f"{array_key}.item"):
            buf.append(item)
            total += 1
            if len(buf) >= per_chunk:
                idx += 1
                _flush(buf, idx)
                buf = []
    if buf:
        idx += 1
        _flush(buf, idx)

    if total == 0:
        raise ValueError(f"No '{array_key}' items found in {src}")

    src.unlink()
    logger.info(f"Chunked {src.name}: {total} {array_key} → {idx} files")
    return idx

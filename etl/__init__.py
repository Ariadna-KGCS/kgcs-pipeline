"""
KGCS ETL package.

Load order is STRICT — each step's relationships require prior steps' nodes.
See scripts/run_all_etl.py for the canonical execution sequence.

Import order when using individual loaders:
    from etl.neo4j_writer import Neo4jWriter
    from etl.init_constraints import run_constraints
    from etl.load_cpe import CPELoader
    from etl.load_cve import CVELoader
    from etl.load_cvss import CVSSLoader
    from etl.load_cwe import CWELoader
    from etl.load_capec import CAPECLoader
    from etl.load_attck import ATTCKLoader
    from etl.load_d3fend import D3FENDLoader
    from etl.load_car import CARLoader
    from etl.load_shield import SHIELDLoader
    from etl.load_engage import ENGAGELoader
"""

from .base         import AbstractETL
from .neo4j_writer import Neo4jWriter
from .load_cpe     import CPELoader
from .load_cve     import CVELoader
from .load_cvss    import CVSSLoader
from .load_cwe     import CWELoader
from .load_capec   import CAPECLoader
from .load_attck   import ATTCKLoader
from .load_d3fend  import D3FENDLoader
from .load_car     import CARLoader
from .load_shield  import SHIELDLoader
from .load_engage  import ENGAGELoader

__all__ = [
    "AbstractETL",
    "Neo4jWriter",
    "CPELoader",
    "CVELoader",
    "CVSSLoader",
    "CWELoader",
    "CAPECLoader",
    "ATTCKLoader",
    "D3FENDLoader",
    "CARLoader",
    "SHIELDLoader",
    "ENGAGELoader",
]

"""Pytest configuration for integration tests."""

from __future__ import annotations

import sys
from importlib import import_module
from importlib.util import find_spec
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT, Path(__file__).resolve().parent):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

# Home Assistant installs its validation compatibility layer during import.
# Match real startup before any integration module can bind the old library.
# The standalone client tests can still run when Home Assistant is absent.
if find_spec("homeassistant") is not None:
    import_module("homeassistant")

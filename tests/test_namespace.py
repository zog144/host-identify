"""Regression coverage for the aggregate Zog namespace layout."""
from pathlib import Path
import re

from zog import host_identify


def test_canonical_namespace_and_version():
    assert host_identify.__name__ == "zog.host_identify"
    assert host_identify.__version__ == "0.3.5"


def test_legacy_top_level_package_does_not_return():
    repository = Path(__file__).resolve().parents[1]
    assert not (repository / "host_identify").exists()
    assert not (repository / "src" / "zog" / "__init__.py").exists()
    legacy = re.compile(
        r"(?m)^\s*(?:from|import)\s+host_identify\b|"
        r"[\"']host_identify\.|python(?:3)?\s+-m\s+host_identify\b"
    )
    for base in (repository / "src", repository / "tests"):
        for path in base.rglob("*.py"):
            if path == Path(__file__):
                continue
            assert not legacy.search(path.read_text()), path
    metadata = (repository / "pyproject.toml").read_text()
    assert '"host_identify.' not in metadata
    assert "'host_identify." not in metadata

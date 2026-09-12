"""Bootstrap tests for basebreak package initialization and metadata."""

import importlib
import importlib.metadata

import basebreak


def test_import_basebreak() -> None:
    """Verify that the basebreak package can be imported and has valid module spec."""
    mod = importlib.import_module("basebreak")
    assert mod is not None
    assert mod.__name__ == "basebreak"


def test_version_coherence() -> None:
    """Verify package version is declared, non-empty, and coherent semver string."""
    assert hasattr(basebreak, "__version__")
    assert isinstance(basebreak.__version__, str)
    assert basebreak.__version__ == "0.1.0"
    parts = basebreak.__version__.split(".")
    assert len(parts) >= 3
    assert all(part.isdigit() for part in parts[:3])


def test_distribution_metadata() -> None:
    """Verify that installed distribution metadata matches package __version__."""
    dist_version = importlib.metadata.version("basebreak")
    assert dist_version == basebreak.__version__

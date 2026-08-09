from importlib.metadata import version

from resonance import __version__


def test_runtime_and_distribution_versions_match() -> None:
    assert version("resonance-alert") == __version__

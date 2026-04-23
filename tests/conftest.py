"""
Pytest configuration for handling slow tests via a --runslow flag.

Usage:
  - Mark slow tests with @pytest.mark.slow
  - Run all tests but skip slow ones:
        pytest
  - Run all tests including slow ones:
        pytest --runslow
"""

# Third-Party Libraries
import pytest


def pytest_addoption(parser):
    """Add the --runslow command-line option to pytest."""
    parser.addoption(
        "--runslow",
        action="store_true",
        default=False,
        help="run tests marked as slow",
    )


def pytest_configure(config):
    """Register the 'slow' marker with pytest."""
    config.addinivalue_line("markers", "slow: mark test as slow")


def pytest_collection_modifyitems(config, items):
    """Skip tests marked 'slow' unless --runslow is given."""
    if config.getoption("--runslow"):
        # --runslow given on the command line: do not skip slow tests
        return

    skip_slow = pytest.mark.skip(reason="need --runslow option to run this test")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip_slow)

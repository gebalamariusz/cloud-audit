"""cloud-audit - Scan your cloud infrastructure for security, cost, and reliability issues."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cloud-audit")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"

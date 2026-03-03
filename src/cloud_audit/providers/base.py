"""Abstract base class for cloud providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

# A check is a callable that returns a CheckResult
CheckFn = Any  # Callable[[], CheckResult] - simplified for Python 3.10 compat


class BaseProvider(ABC):
    """Base class that all cloud providers must implement."""

    @abstractmethod
    def get_account_id(self) -> str:
        """Return the account/subscription identifier."""

    @abstractmethod
    def get_checks(self, categories: list[str] | None = None) -> list[CheckFn]:
        """Return list of check functions to execute.

        Args:
            categories: Optional filter - only return checks for these categories.
        """

    @abstractmethod
    def get_provider_name(self) -> str:
        """Return provider name (e.g. 'aws', 'azure')."""

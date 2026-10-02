from typing import Protocol

from .models import ScanResult


class NetworkScanner(Protocol):
    async def scan(self, target: str) -> ScanResult: ...


class ScannerError(RuntimeError):
    """A safe, user-presentable scanner failure."""


class ScanCancelled(ScannerError):
    pass

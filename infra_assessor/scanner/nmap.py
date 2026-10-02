import asyncio
import ipaddress
import os
import shutil

from .base import ScanCancelled, ScannerError
from .models import ScanResult
from .parser import parse_nmap_xml

PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def validate_target(value: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 network in canonical CIDR notation.") from exc
    if network.version != 4:
        raise ValueError("Only IPv4 networks are supported.")
    if not any(network.subnet_of(allowed) for allowed in PRIVATE_NETWORKS):
        raise ValueError("Target must be wholly within an RFC1918 private network.")
    return str(network)


class NmapScanner:
    async def scan(self, target: str) -> ScanResult:
        target = validate_target(target)
        binary = shutil.which("nmap")
        if not binary:
            raise ScannerError("Nmap is not installed or is not available on PATH.")
        privileged = os.geteuid() == 0
        args = [binary, "-sT", "-T3", "--top-ports", "1000", "-sV", "--version-light", "-oX", "-"]
        if privileged:
            args += ["-O", "--osscan-limit"]
        # The validated target is passed as one argv element; no shell is involved.
        args.append(target)
        try:
            process = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
        except asyncio.CancelledError as exc:
            if "process" in locals() and process.returncode is None:
                process.terminate()
            raise ScanCancelled("Assessment scan was cancelled.") from exc
        if process.returncode != 0:
            detail = stderr.decode(errors="replace").strip().splitlines()[-1:]
            raise ScannerError(f"Nmap failed: {detail[0] if detail else 'unknown error'}")
        result = parse_nmap_xml(stdout.decode(errors="replace"), target)
        if not privileged:
            result.warnings.append(
                "OS detection and raw-packet discovery were unavailable "
                "without elevated privileges."
            )
        return result

import asyncio
import hashlib
import re
import socket
import ssl
import struct
from datetime import UTC, datetime

from infra_assessor.scanner.models import EvidenceState, ProbeEvidence, ServiceObservation

from .base import ServiceProbe

TIMEOUT = 3.0


def parse_tls_certificate(
    cert: dict[str, object], hostname: str | None = None
) -> dict[str, object]:
    """Normalise the certificate dictionary returned by ``SSLSocket.getpeercert``."""
    subject = dict(item for group in cert.get("subject", ()) for item in group)
    issuer = dict(item for group in cert.get("issuer", ()) for item in group)
    sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")
    now = datetime.now(UTC).timestamp()
    result: dict[str, object] = {
        "subject": subject,
        "issuer": issuer,
        "sans": sans,
        "not_before": not_before,
        "not_after": not_after,
        "not_yet_valid": bool(not_before and ssl.cert_time_to_seconds(str(not_before)) > now),
        "expired": bool(not_after and ssl.cert_time_to_seconds(str(not_after)) < now),
    }
    if hostname:
        candidate_names = sans or [str(subject.get("commonName", ""))]
        hostname = hostname.lower().rstrip(".")
        result["hostname_matches"] = any(
            hostname == name.lower().rstrip(".")
            or (
                name.startswith("*.")
                and hostname.endswith(name[1:].lower())
                and hostname.count(".") == name.count(".")
            )
            for name in candidate_names
        )
    return result


async def _connect(host: str, port: int, ssl_context: ssl.SSLContext | None = None):
    return await asyncio.wait_for(
        asyncio.open_connection(
            host, port, ssl=ssl_context, server_hostname=host if ssl_context else None
        ),
        TIMEOUT,
    )


def failure(name: str, target: str, exc: Exception) -> ProbeEvidence:
    kind = "timeout" if isinstance(exc, TimeoutError) else "failed"
    return ProbeEvidence(
        probe_type=name,
        target=target,
        outcome=kind,
        summary=f"{name} attempted but no valid response was received.",
        error=type(exc).__name__,
    )


class TlsProbe(ServiceProbe):
    name = "TLS"

    def can_probe(self, service: ServiceObservation) -> bool:
        return service.protocol == "tcp" and (
            service.port in {443, 465, 636, 8443, 9443}
            or "ssl" in service.name
            or "https" in service.name
        )

    async def probe(self, host: str, service: ServiceObservation) -> ProbeEvidence:
        target = f"{host}:{service.port}"
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            reader, writer = await _connect(host, service.port, context)
            ssl_object = writer.get_extra_info("ssl_object")
            cert = ssl_object.getpeercert(binary_form=True) if ssl_object else None
            decoded = {}
            if cert:
                # DER is retained only as a hash; full metadata is not always available.
                decoded["certificate_sha256"] = hashlib.sha256(cert).hexdigest()
            decoded["tls_version"] = ssl_object.version() if ssl_object else None
            writer.close()
            await writer.wait_closed()
            return ProbeEvidence(
                probe_type=self.name,
                target=target,
                outcome="confirmed",
                summary=f"TLS negotiation succeeded using {decoded['tls_version']}.",
                state=EvidenceState.confirmed,
                details=decoded,
            )
        except (OSError, ssl.SSLError, TimeoutError) as exc:
            return failure(self.name, target, exc)


class HttpProbe(ServiceProbe):
    name = "HTTP"

    def can_probe(self, service: ServiceObservation) -> bool:
        return service.protocol == "tcp" and (
            service.port in {80, 443, 8000, 8008, 8080, 8081, 8443, 8888} or "http" in service.name
        )

    async def _request(self, host: str, port: int, tls: bool) -> dict[str, object]:
        context = None
        if tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        reader, writer = await _connect(host, port, context)
        request = (
            f"GET / HTTP/1.1\r\nHost: {host}\r\n"
            "User-Agent: Blindspot/0.1.3\r\nConnection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(131072), TIMEOUT)
        writer.close()
        await writer.wait_closed()
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1", "replace").splitlines()
        if not lines or not lines[0].startswith("HTTP/"):
            raise ValueError("not an HTTP response")
        headers: dict[str, str] = {}
        cookies = []
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                if key.lower() == "set-cookie":
                    cookies.append(value.strip())
                else:
                    headers[key.lower()] = value.strip()
        title_match = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        title = (
            re.sub(r"\s+", " ", title_match.group(1).decode("utf-8", "replace")).strip()
            if title_match
            else None
        )
        status = int(lines[0].split()[1])
        return {
            "scheme": "https" if tls else "http",
            "status": status,
            "server": headers.get("server"),
            "content_type": headers.get("content-type"),
            "www_authenticate": headers.get("www-authenticate"),
            "location": headers.get("location"),
            "redirects_to_https": headers.get("location", "").lower().startswith("https://"),
            "title": title,
            "cookies": cookies,
            "security_headers": {
                k: headers[k]
                for k in (
                    "strict-transport-security",
                    "content-security-policy",
                    "x-frame-options",
                    "x-content-type-options",
                )
                if k in headers
            },
            "response_sha256": hashlib.sha256(body).hexdigest(),
            "authentication_required": status in {401, 403},
        }

    async def probe(self, host: str, service: ServiceObservation) -> ProbeEvidence:
        target = f"{host}:{service.port}"
        errors = []
        # Test TLS and plaintext independently; a conventional port is only a hint.
        for tls in (True, False):
            try:
                details = await self._request(host, service.port, tls)
                scheme = str(details["scheme"])
                return ProbeEvidence(
                    probe_type=self.name,
                    target=target,
                    outcome="confirmed",
                    summary=f"{scheme.upper()} returned status {details['status']}.",
                    state=EvidenceState.confirmed,
                    details=details,
                )
            except (OSError, ssl.SSLError, TimeoutError, ValueError) as exc:
                errors.append(type(exc).__name__)
        return ProbeEvidence(
            probe_type=self.name,
            target=target,
            outcome="failed",
            summary="HTTP and HTTPS requests produced no valid HTTP response.",
            error=", ".join(errors),
        )


class SshProbe(ServiceProbe):
    name = "SSH"

    def can_probe(self, service: ServiceObservation) -> bool:
        return service.port == 22 or "ssh" in service.name

    async def probe(self, host: str, service: ServiceObservation) -> ProbeEvidence:
        target = f"{host}:{service.port}"
        try:
            reader, writer = await _connect(host, service.port)
            banner = (
                (await asyncio.wait_for(reader.readline(), TIMEOUT))
                .decode("ascii", "replace")
                .strip()
            )
            writer.close()
            await writer.wait_closed()
            if not banner.startswith("SSH-"):
                raise ValueError("invalid SSH banner")
            parts = banner.split("-", 2)
            return ProbeEvidence(
                probe_type=self.name,
                target=target,
                outcome="confirmed",
                state=EvidenceState.confirmed,
                summary=f"SSH protocol banner received: {banner[:200]}",
                details={
                    "banner": banner[:500],
                    "protocol_version": parts[1],
                    "implementation": parts[2] if len(parts) > 2 else None,
                },
            )
        except (OSError, TimeoutError, ValueError) as exc:
            return failure(self.name, target, exc)


class PostgresProbe(ServiceProbe):
    name = "PostgreSQL"

    def can_probe(self, service: ServiceObservation) -> bool:
        return service.port == 5432 or "postgres" in service.name

    async def probe(self, host: str, service: ServiceObservation) -> ProbeEvidence:
        target = f"{host}:{service.port}"
        try:
            reader, writer = await _connect(host, service.port)
            writer.write(struct.pack("!II", 8, 80877103))
            await writer.drain()
            answer = await asyncio.wait_for(reader.readexactly(1), TIMEOUT)
            details = {
                "tls_supported": answer == b"S",
                "ssl_response": answer.decode("ascii", "replace"),
                "authentication_attempted": False,
            }
            writer.close()
            await writer.wait_closed()
            if answer not in {b"S", b"N"}:
                raise ValueError("invalid PostgreSQL SSL response")
            return ProbeEvidence(
                probe_type=self.name,
                target=target,
                outcome="confirmed",
                state=EvidenceState.confirmed,
                summary=(
                    "PostgreSQL protocol confirmed; TLS "
                    f"{'is' if answer == b'S' else 'is not'} supported. "
                    "Authentication was not attempted."
                ),
                details=details,
            )
        except (OSError, TimeoutError, ValueError, asyncio.IncompleteReadError) as exc:
            return failure(self.name, target, exc)


class DnsProbe(ServiceProbe):
    name = "DNS"

    def can_probe(self, service: ServiceObservation) -> bool:
        return service.port == 53 or service.name in {"domain", "dns"}

    async def probe(self, host: str, service: ServiceObservation) -> ProbeEvidence:
        target = f"{host}:{service.port}"
        try:
            query_id = 0xB113
            qname = b"\x07example\x03com\x00"
            packet = (
                struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
                + qname
                + struct.pack("!HH", 1, 1)
            )
            loop = asyncio.get_running_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            try:
                await loop.sock_sendto(sock, packet, (host, service.port))
                data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 4096), TIMEOUT)
            finally:
                sock.close()
            if len(data) < 12 or struct.unpack("!H", data[:2])[0] != query_id:
                raise ValueError("invalid DNS response")
            flags = struct.unpack("!H", data[2:4])[0]
            answers = struct.unpack("!H", data[6:8])[0]
            recursion = bool(flags & 0x80)
            return ProbeEvidence(
                probe_type=self.name,
                target=target,
                outcome="confirmed",
                state=EvidenceState.confirmed,
                summary=(
                    "DNS protocol confirmed; recursion "
                    f"{'available' if recursion else 'not advertised'} for the test query."
                ),
                details={
                    "recursion_available": recursion,
                    "answer_count": answers,
                    "external_query": "example.com",
                },
            )
        except (OSError, TimeoutError, ValueError) as exc:
            return failure(self.name, target, exc)


class SmbProbe(ServiceProbe):
    name = "SMB"

    def can_probe(self, service: ServiceObservation) -> bool:
        return service.port in {139, 445} or "smb" in service.name or "microsoft-ds" in service.name

    async def probe(self, host: str, service: ServiceObservation) -> ProbeEvidence:
        target = f"{host}:{service.port}"
        # SMB2 NEGOTIATE with common dialects; no session setup, authentication or share access.
        body = bytes.fromhex(
            "fe534d4240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000024000500010000000000000000000000000000000000000078563412000000000202100222022402"
        )
        packet = len(body).to_bytes(4, "big") + body
        try:
            reader, writer = await _connect(host, service.port)
            writer.write(packet)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), TIMEOUT)
            writer.close()
            await writer.wait_closed()
            if len(data) < 72 or data[4:8] != b"\xfeSMB":
                raise ValueError("invalid SMB2 response")
            security_mode = struct.unpack_from("<H", data, 70)[0]
            return ProbeEvidence(
                probe_type=self.name,
                target=target,
                outcome="confirmed",
                state=EvidenceState.confirmed,
                summary="SMB2/3 negotiation response received without authentication.",
                details={
                    "family": "SMB2/3",
                    "signing_enabled": bool(security_mode & 1),
                    "signing_required": bool(security_mode & 2),
                    "authentication_attempted": False,
                },
            )
        except (OSError, TimeoutError, ValueError) as exc:
            return failure(self.name, target, exc)


PROBES = (TlsProbe(), HttpProbe(), DnsProbe(), PostgresProbe(), SshProbe(), SmbProbe())

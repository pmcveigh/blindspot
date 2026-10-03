from .models import DeviceObservation


def classify_device(
    device: DeviceObservation, *, include_evidence: bool = False
) -> tuple[str, float] | tuple[str, float, list[str]]:
    """Classify using corroborating host-level signals, not a decisive single port."""
    ports = {s.port for s in device.services}
    text = " ".join(
        filter(
            None,
            [device.hostname, device.mac_vendor, device.os_guess]
            + [s.product for s in device.services if s.product],
        )
    ).lower()
    scores: dict[str, float] = {}
    evidence: dict[str, list[str]] = {}

    def add(kind: str, weight: float, reason: str) -> None:
        scores[kind] = scores.get(kind, 0) + weight
        evidence.setdefault(kind, []).append(reason)

    if 9100 in ports:
        add("printer", 0.3, "JetDirect-compatible port 9100 observed")
    if 631 in ports:
        add("printer", 0.3, "IPP printing port observed")
    if any(x in text for x in ("printer", "laserjet", "epson", "brother", "xerox")):
        add("printer", 0.45, "Printer identity or vendor evidence observed")
    if ports & {3306, 5432, 1433, 445, 25}:
        add("server", 0.45, "Infrastructure or application server service detected")
    if any(x in text for x in ("apache", "nginx", "postgres", "mysql", "dnsmasq", "pi-hole")):
        add("server", 0.35, "Server software product detected")
    if len(ports) >= 4:
        add("server", 0.2, "Multiple infrastructure services present")
    if ports & {5060, 5061}:
        add("PBX/voice system", 0.35, "SIP port observed")
    if any(x in text for x in ("pbx", "asterisk", "voip")):
        add("PBX/voice system", 0.5, "Voice system identity detected")
    if any(x in text for x in ("synology", "qnap", " nas")):
        add("NAS/storage", 0.8, "Storage product identity detected")
    if any(x in text for x in ("router", "firewall", "pfsense", "fortigate")):
        add("router/firewall", 0.65, "Router or firewall identity detected")
    if {53, 80, 443}.issubset(ports):
        add("router/firewall", 0.35, "DNS and web administration service mix observed")
    if 1900 in ports:
        add("router/firewall", 0.2, "UPnP service observed")
    if any(x in text for x in ("access point", "wireless", "unifi ap")):
        add("wireless access point", 0.7, "Wireless product identity detected")
    if any(x in text for x in ("switch", "procurve")):
        add("switch", 0.65, "Network switch identity detected")
    if any(x in text for x in ("windows", "mac os", "desktop", "laptop")):
        add("workstation", 0.5, "Workstation operating-system evidence observed")

    if not scores:
        result = ("unknown", 0.2, ["Available evidence was insufficient to classify the device"])
    else:
        ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        kind, score = ranked[0]
        conflict = len(ranked) > 1 and ranked[1][1] >= score * 0.75
        confidence = min(0.9, 0.35 + score / 2)
        if conflict:
            confidence = max(0.3, confidence - 0.15)
            evidence[kind].append(f"Conflicting {ranked[1][0]} evidence reduced confidence")
        result = (kind, confidence, evidence[kind])
    return result if include_evidence else result[:2]

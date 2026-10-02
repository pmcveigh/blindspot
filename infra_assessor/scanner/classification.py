from .models import DeviceObservation


def classify_device(device: DeviceObservation) -> tuple[str, float]:
    ports = {s.port for s in device.services}
    text = " ".join(
        filter(
            None,
            [device.hostname, device.mac_vendor, device.os_guess]
            + [s.product for s in device.services if s.product],
        )
    ).lower()
    if ports & {5060, 5061} or any(x in text for x in ("pbx", "asterisk", "voip")):
        return "PBX/voice system", 0.85
    if any(x in text for x in ("printer", "jetdirect", "laserjet")) or 9100 in ports:
        return "printer", 0.85
    if any(x in text for x in ("synology", "qnap", "nas")):
        return "NAS/storage", 0.85
    if any(x in text for x in ("access point", "wireless", "unifi ap")):
        return "wireless access point", 0.75
    if any(x in text for x in ("switch", "procurve")):
        return "switch", 0.7
    if any(x in text for x in ("router", "firewall", "pfsense", "fortigate")) or {
        53,
        80,
        443,
    }.issubset(ports):
        return "router/firewall", 0.65
    if ports & {3306, 5432, 1433, 445, 25} or len(ports) >= 5:
        return "server", 0.65
    if any(x in text for x in ("windows", "mac os", "desktop", "laptop")):
        return "workstation", 0.55
    return "unknown", 0.2

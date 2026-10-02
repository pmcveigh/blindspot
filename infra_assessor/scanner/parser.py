import xml.etree.ElementTree as ET

from .base import ScannerError
from .classification import classify_device
from .models import DeviceObservation, ScanResult, ServiceObservation


def parse_nmap_xml(xml: str, target: str) -> ScanResult:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise ScannerError("Nmap returned malformed XML output.") from exc
    devices: list[DeviceObservation] = []
    for host in root.findall("host"):
        if (status := host.find("status")) is not None and status.get("state") != "up":
            continue
        addresses = {a.get("addrtype"): a for a in host.findall("address")}
        ipv4 = addresses.get("ipv4")
        if ipv4 is None or not ipv4.get("addr"):
            continue
        mac = addresses.get("mac")
        names = host.findall("./hostnames/hostname")
        services = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            services.append(
                ServiceObservation(
                    port=int(port.get("portid", "0")),
                    protocol=port.get("protocol", "tcp"),
                    state="open",
                    name=svc.get("name", "unknown") if svc is not None else "unknown",
                    product=svc.get("product") if svc is not None else None,
                    version=svc.get("version") if svc is not None else None,
                    extra_info=svc.get("extrainfo") if svc is not None else None,
                )
            )
        osmatch = host.find("./os/osmatch")
        device = DeviceObservation(
            ip_address=ipv4.get("addr", ""),
            mac_address=mac.get("addr") if mac is not None else None,
            mac_vendor=mac.get("vendor") if mac is not None else None,
            hostname=names[0].get("name") if names else None,
            os_guess=osmatch.get("name") if osmatch is not None else None,
            services=services,
        )
        device.device_type, device.classification_confidence = classify_device(device)
        devices.append(device)
    return ScanResult(target=target, devices=devices)

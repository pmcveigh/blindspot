from pathlib import Path

import yaml
from pydantic import BaseModel

from infra_assessor.scanner.models import Severity


class Match(BaseModel):
    service_names: list[str] | None = None
    ports: list[int] | None = None
    plain_http: bool = False
    min_tcp_services: int | None = None
    device_type: str | None = None


class Rule(BaseModel):
    id: str
    title: str
    severity: Severity
    match: Match
    technical_description: str
    customer_description: str
    recommendation: str
    commercial_category: str


def load_rules(path: Path | None = None) -> list[Rule]:
    path = path or Path(__file__).with_name("rules") / "default.yaml"
    return [Rule.model_validate(item) for item in yaml.safe_load(path.read_text())]

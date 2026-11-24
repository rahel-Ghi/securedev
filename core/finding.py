from enum import Enum
from pydantic import BaseModel


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    tool: str
    rule: str
    category: str          # secret, dependency, code, dockerfile, image, dynamic
    severity: Severity
    location: str          # file:line, package, or URL
    cve: str | None = None
    fingerprint: str = ""
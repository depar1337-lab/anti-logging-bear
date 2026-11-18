# Anti-Logging Bear by Priest

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()


class Verdict(enum.Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"

    @property
    def headline(self) -> str:
        return {
            Verdict.CLEAN: "No threats found",
            Verdict.SUSPICIOUS: "Suspicious - be careful",
            Verdict.DANGEROUS: "Dangerous - don't open this",
        }[self]

    @property
    def exit_code(self) -> int:
        return {Verdict.CLEAN: 0, Verdict.SUSPICIOUS: 1, Verdict.DANGEROUS: 2}[self]


@dataclass
class Finding:
    path: str
    check: str
    severity: Severity
    title: str
    detail: str = ""
    indicators: list[str] = field(default_factory=list)

    def key(self) -> tuple:
        return (self.path, self.check, self.title)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "check": self.check,
            "severity": self.severity.name.lower(),
            "title": self.title,
            "detail": self.detail,
            "indicators": list(self.indicators),
        }


@dataclass
class FileRecord:
    path: str
    size: int
    sha256: str
    kind: str

    def to_dict(self) -> dict:
        return {"path": self.path, "size": self.size, "sha256": self.sha256, "kind": self.kind}


@dataclass
class ScanReport:
    target: str
    files: list[FileRecord] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    engines: dict[str, str] = field(default_factory=dict)
    duration: float = 0.0
    strict: bool = False

    def add(self, finding: Finding) -> None:
        if all(f.key() != finding.key() for f in self.findings):
            self.findings.append(finding)

    def extend(self, findings: list[Finding]) -> None:
        for f in findings:
            self.add(f)

    @property
    def worst(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    @property
    def verdict(self) -> Verdict:
        worst = self.worst
        if worst >= Severity.CRITICAL:
            return Verdict.DANGEROUS
        if worst >= Severity.HIGH or (self.strict and worst >= Severity.MEDIUM):
            return Verdict.SUSPICIOUS
        return Verdict.CLEAN

    def ranked(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity, f.path, f.check))

    def indicators(self) -> list[str]:
        seen: list[str] = []
        for f in self.findings:
            for ioc in f.indicators:
                if ioc not in seen:
                    seen.append(ioc)
        return seen

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "verdict": self.verdict.value,
            "duration": round(self.duration, 3),
            "engines": dict(self.engines),
            "files": [r.to_dict() for r in self.files],
            "findings": [f.to_dict() for f in self.ranked()],
        }

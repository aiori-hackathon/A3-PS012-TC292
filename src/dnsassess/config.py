from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

import yaml


class ConfigError(Exception):
    """Raised when configuration is missing or invalid."""


@dataclass
class Authorisation:
    owner: str
    authorised_by: str
    authorised_on: str
    statement: str

    def is_complete(self) -> bool:
        return bool(
            self.owner
            and self.authorised_by
            and self.authorised_on
            and self.statement
        )


@dataclass
class Target:
    id: str
    name: str
    ip: str
    serves_zone: str | None = None


@dataclass
class ScopeConfig:
    authorisation: Authorisation
    test_zone: str
    test_zone_ip: str
    targets: list[Target] = field(default_factory=list)

    def by_ip(self, ip: str) -> Target | None:
        for target in self.targets:
            if target.ip == ip:
                return target
        return None

    def by_id(self, target_id: str) -> Target | None:
        for target in self.targets:
            if target.id == target_id:
                return target
        return None


@dataclass
class RateConfig:
    global_qps: float
    per_target_qps: float
    max_queries_per_target: int
    timeout_seconds: float
    max_total_queries: int
    edns_payload: int
    udp_retries: int = 2


def _require(data: dict, key: str, path: str):
    if key not in data:
        raise ConfigError(f"{path}: missing required key '{key}'")
    return data[key]


def load_scope(path: str | Path) -> ScopeConfig:
    """Load scope.yaml and return a validated ScopeConfig."""
    path = Path(path)
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    auth_data = _require(data, "authorisation", str(path))
    authorisation = Authorisation(
        owner=_require(auth_data, "owner", f"{path}.authorisation"),
        authorised_by=_require(auth_data, "authorised_by", f"{path}.authorisation"),
        authorised_on=_require(auth_data, "authorised_on", f"{path}.authorisation"),
        statement=_require(auth_data, "statement", f"{path}.authorisation"),
    )
    if not authorisation.is_complete():
        raise ConfigError(f"{path}: authorisation block is incomplete")

    test_zone = _require(data, "test_zone", str(path))
    test_zone_ip = _require(data, "test_zone_ip", str(path))

    raw_targets = _require(data, "targets", str(path))
    if len(raw_targets) > 20:
        raise ConfigError(
            f"{path}: at most 20 targets allowed, got {len(raw_targets)}"
        )

    targets = [
        Target(
            id=_require(entry, "id", f"{path}.targets"),
            name=_require(entry, "name", f"{path}.targets"),
            ip=_require(entry, "ip", f"{path}.targets"),
            serves_zone=entry.get("serves_zone"),
        )
        for entry in raw_targets
    ]

    return ScopeConfig(
        authorisation=authorisation,
        test_zone=test_zone,
        test_zone_ip=test_zone_ip,
        targets=targets,
    )


def load_rate(path: str | Path) -> RateConfig:
    """Load rate.yaml and return a validated RateConfig."""
    path = Path(path)
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    udp_retries = int(data.get("udp_retries", 2))
    if udp_retries < 0:
        raise ConfigError(f"{path}: udp_retries must be >= 0, got {udp_retries}")

    return RateConfig(
        global_qps=float(_require(data, "global_qps", str(path))),
        per_target_qps=float(_require(data, "per_target_qps", str(path))),
        max_queries_per_target=int(
            _require(data, "max_queries_per_target", str(path))
        ),
        timeout_seconds=float(_require(data, "timeout_seconds", str(path))),
        max_total_queries=int(_require(data, "max_total_queries", str(path))),
        edns_payload=int(_require(data, "edns_payload", str(path))),
        udp_retries=udp_retries,
    )


def config_hash(scope_path: str | Path, rate_path: str | Path) -> str:
    """SHA-256 of both config files, for report metadata."""
    digest = hashlib.sha256()
    for p in (scope_path, rate_path):
        digest.update(Path(p).read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()

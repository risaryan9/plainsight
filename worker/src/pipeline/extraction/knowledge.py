"""Loads the curated data files from ``worker/data`` (spec §20.2: data, not if-chains)."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

DATA_DIR_ENV = "PLAINSIGHT_DATA_DIR"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class MethodRule(_Model):
    class_name: str = Field(alias="class")
    names: tuple[str, ...]


class CapabilityRule(_Model):
    description: str | None = None
    satisfied_by: tuple[str, ...] = ()
    methods: tuple[MethodRule, ...] = ()
    class_prefixes: tuple[str, ...] = ()
    strings: tuple[str, ...] = ()


class SdkSignature(_Model):
    prefix: str
    name: str
    category: str


class ComponentRule(_Model):
    type: Literal["activity", "service", "receiver", "provider"]
    actions: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()


class HighRiskRule(_Model):
    description: str | None = None
    permissions: tuple[str, ...] = ()
    component: ComponentRule | None = None
    class_init: tuple[str, ...] = ()
    file_pattern: str | None = None


class Knowledge(_Model):
    permission_map: dict[str, str]
    sensitive_apis: dict[str, CapabilityRule]
    sdk_signatures: tuple[SdkSignature, ...]
    high_risk_features: dict[str, HighRiskRule]


def data_dir() -> Path:
    """Find the data directory: env override, packaged copy, source tree, Lambda layout."""
    here = Path(__file__).resolve()
    candidates = [
        here.parents[1] / "_data",  # packaged inside a built wheel
        here.parents[3] / "data",  # source tree: worker/data
        here.parents[2] / "data",  # Lambda image: ${LAMBDA_TASK_ROOT}/data
    ]
    override = os.environ.get(DATA_DIR_ENV)
    if override:
        candidates.insert(0, Path(override))
    for candidate in candidates:
        if (candidate / "permission_map.yaml").is_file():
            return candidate
    raise FileNotFoundError(
        f"Extraction data files not found. Set {DATA_DIR_ENV} or check: "
        + ", ".join(str(c) for c in candidates)
    )


@lru_cache(maxsize=1)
def load_knowledge() -> Knowledge:
    """Load and validate all data files. Cached for the life of the process."""
    root = data_dir()
    with open(root / "permission_map.yaml", encoding="utf-8") as fh:
        permission_map = yaml.safe_load(fh)
    with open(root / "sensitive_apis.yaml", encoding="utf-8") as fh:
        sensitive_apis = yaml.safe_load(fh)
    with open(root / "sdk_signatures.json", encoding="utf-8") as fh:
        sdk_signatures = json.load(fh)["signatures"]
    with open(root / "high_risk_features.yaml", encoding="utf-8") as fh:
        high_risk_features = yaml.safe_load(fh)
    return Knowledge.model_validate(
        {
            "permission_map": permission_map,
            "sensitive_apis": sensitive_apis,
            "sdk_signatures": sdk_signatures,
            "high_risk_features": high_risk_features,
        }
    )

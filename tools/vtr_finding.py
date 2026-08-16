"""
VTR Finding Schema v1
cobol-shield — compatible con cryptofault y vtr-forensic-img

Contrato de datos compartido del ecosistema VTR.
Cada herramienta produce Findings con este schema.
El correlador VTR Case agrupa por asset_id sin lógica especial.

Decisión de diseño:
  asset_id nunca es null. Si no hay inventario pasivo,
  se usa proxy "file:<nombre>" con asset_id_status: "UNRESOLVED".
  Cuando exista vtr-asset, UNRESOLVED → asset_id real sin romper schema.

Copyright (C) 2026 Luis Fidel Castellanos Diaz
Vector Telemetry Research (VTR) — SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

SCHEMA_VERSION = "1"
TOOL_NAME = "cobol-shield"
TOOL_VERSION = "0.3.0"

# asset_id_status values — compatible con context_status de vtr-forensic-img
ASSET_UNRESOLVED = "UNRESOLVED"    # no hay inventario pasivo, proxy por archivo
ASSET_OBSERVED = "OBSERVED"        # identificado en source, no verificado
ASSET_CORROBORATED = "CORROBORATED"
ASSET_VERIFIED = "VERIFIED"

# context_status values
CTX_OBSERVED = "OBSERVED"
CTX_UNVERIFIED = "UNVERIFIED"
CTX_CORROBORATED = "CORROBORATED"
CTX_VERIFIED = "VERIFIED"
CTX_REJECTED = "REJECTED"

# classification — alineado con Audit Master Prompt VTR
CLASS_HECHO = "HECHO"
CLASS_INFERENCIA = "INFERENCIA"
CLASS_PROYECCION = "PROYECCION"

# severity
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"
SEV_INFO = "info"

# confidence
CONF_OBSERVED = "OBSERVED"
CONF_INFERRED = "INFERRED"
CONF_PROJECTED = "PROJECTED"


@dataclass
class Provenance:
    """Cadena de custodia del finding."""
    file: str
    line: Optional[int]
    file_sha256: str
    compiler: Optional[str] = None
    copybook: Optional[str] = None


@dataclass
class Finding:
    """
    VTR Finding Schema v1.
    Producido por cobol-shield, consumido por cryptofault y vtr-forensic-img
    via context_loader.py.
    """
    # Identidad
    finding_id: str
    asset_id: str               # nunca null — "file:<name>" si UNRESOLVED
    asset_id_status: str        # UNRESOLVED | OBSERVED | CORROBORATED | VERIFIED

    # Trazabilidad de herramienta
    source_tool: str
    tool_version: str
    schema_version: str
    timestamp: str

    # Observación
    observation: str
    severity: str
    confidence: str             # OBSERVED | INFERRED | PROJECTED
    classification: str         # HECHO | INFERENCIA | PROYECCION

    # Referencia de evidencia — archivo:línea:sha256
    evidence_ref: str

    # Estado de contexto
    context_status: str         # OBSERVED | UNVERIFIED | CORROBORATED | VERIFIED | REJECTED

    # Provenance — cadena de custodia
    provenance: Provenance

    # Campos opcionales
    protocol: Optional[str] = None
    rule_id: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


def sha256_file(path: str) -> str:
    """SHA-256 real de un archivo — cadena de custodia."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def make_finding(
    observation: str,
    file_path: str,
    line: int,
    severity: str,
    classification: str,
    confidence: str = CONF_OBSERVED,
    rule_id: Optional[str] = None,
    protocol: Optional[str] = None,
    asset_id: Optional[str] = None,
    compiler: Optional[str] = None,
    copybook: Optional[str] = None,
) -> Finding:
    """
    Factory para crear un Finding con todos los campos requeridos.
    asset_id por defecto es "file:<nombre>" con status UNRESOLVED.
    """
    p = Path(file_path)
    file_sha256 = sha256_file(file_path)
    evidence_ref = f"{p.name}:{line}:sha256:{file_sha256[:16]}"

    resolved_asset_id = asset_id or f"file:{p.name}"
    asset_status = ASSET_OBSERVED if asset_id else ASSET_UNRESOLVED

    return Finding(
        finding_id=str(uuid.uuid4()),
        asset_id=resolved_asset_id,
        asset_id_status=asset_status,
        source_tool=TOOL_NAME,
        tool_version=TOOL_VERSION,
        schema_version=SCHEMA_VERSION,
        timestamp=datetime.now(timezone.utc).isoformat(),
        observation=observation,
        severity=severity,
        confidence=confidence,
        classification=classification,
        evidence_ref=evidence_ref,
        context_status=CTX_OBSERVED,
        provenance=Provenance(
            file=str(p),
            line=line,
            file_sha256=file_sha256,
            compiler=compiler,
            copybook=copybook,
        ),
        protocol=protocol,
        rule_id=rule_id,
    )

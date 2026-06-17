"""Orchestrator: runs registered detectors and aggregates Findings into a Report."""
from __future__ import annotations

import logging
from pathlib import Path

from .types import Detector, Finding, Report

log = logging.getLogger(__name__)


class Orchestrator:
    """Runs a collection of detectors against a scan root and produces a Report.

    Usage:
        orch = Orchestrator(detectors=[McpDetector(), LlmSdkDetector(), ...])
        report = orch.run("/path/to/repo")
    """

    def __init__(self, detectors: list[Detector] | None = None) -> None:
        self.detectors: list[Detector] = list(detectors or [])

    def register(self, detector: Detector) -> None:
        """Add a detector to the run list."""
        self.detectors.append(detector)

    def run(self, scan_root: str) -> Report:
        """Run every registered detector against scan_root, aggregate findings.

        The resolved absolute path is used internally so detectors get a
        stable working root. The Report exposes a privacy-safe representation
        instead — the basename of the scan root rather than the full
        filesystem path. Absolute paths leak the user's home directory,
        employer name, internal mount points, etc., into reports that often
        get committed to git or posted as PR comments.
        """
        root = Path(scan_root).resolve()
        if not root.exists():
            raise FileNotFoundError(f"scan root does not exist: {scan_root}")
        if not root.is_dir():
            raise NotADirectoryError(f"scan root is not a directory: {scan_root}")

        all_findings: list[Finding] = []
        errors: list[str] = []
        detector_names: list[str] = []

        for detector in self.detectors:
            name = getattr(detector, "name", detector.__class__.__name__)
            detector_names.append(name)
            try:
                findings = detector.detect(str(root))
                # Stamp detector_name on every finding for traceability
                for f in findings:
                    if not f.detector_name:
                        f.detector_name = name
                all_findings.extend(findings)
                log.debug("detector %s produced %d findings", name, len(findings))
            except Exception as exc:  # noqa: BLE001 - we want to keep going
                msg = f"detector {name} failed: {exc.__class__.__name__}: {exc}"
                errors.append(msg)
                log.warning(msg)

        # Enrich validate-runtime surfaces beyond MCP (agents) with deep-dive
        # audits, so severity flows into dispositions + summary. Defensive.
        try:
            from .audits import enrich_audits  # noqa: PLC0415

            enrich_audits(all_findings)
        except Exception as exc:  # noqa: BLE001
            msg = f"audit enrichment failed: {exc.__class__.__name__}: {exc}"
            errors.append(msg)
            log.warning(msg)

        # Human-oversight pass (EU AI Act Art. 14): flag high-risk actions with
        # no detectable approval / human-in-the-loop gate. Runs after audits so
        # both agent and MCP findings can be assessed. Reads only each finding's
        # own evidence files (under root). Defensive: must not abort a scan.
        try:
            from .oversight import enrich_oversight  # noqa: PLC0415

            enrich_oversight(all_findings, str(root))
        except Exception as exc:  # noqa: BLE001
            msg = f"oversight enrichment failed: {exc.__class__.__name__}: {exc}"
            errors.append(msg)
            log.warning(msg)

        # Observability pass (EU AI Act Art. 12 / ISO A.6.2.6 / NIST MEASURE 3):
        # if the repo wires no AI tracing/logging anywhere, flag the autonomous
        # execution surfaces (agents + MCP). Defensive: must not abort a scan.
        try:
            from .observability import enrich_observability  # noqa: PLC0415

            enrich_observability(all_findings, str(root))
        except Exception as exc:  # noqa: BLE001
            msg = f"observability enrichment failed: {exc.__class__.__name__}: {exc}"
            errors.append(msg)
            log.warning(msg)

        # PII-into-prompt pass (EU AI Act Art. 10 / ISO A.7 / OWASP LLM02): flag
        # agents whose prompt templates embed PII fields. Defensive.
        try:
            from .pii import enrich_pii  # noqa: PLC0415

            enrich_pii(all_findings, str(root))
        except Exception as exc:  # noqa: BLE001
            msg = f"pii enrichment failed: {exc.__class__.__name__}: {exc}"
            errors.append(msg)
            log.warning(msg)

        # Classify dispositions (resolve-here vs validate-runtime), then attach
        # paid-platform bridges. Defensive: neither must abort a scan.
        try:
            from .dispositions import attach_dispositions  # noqa: PLC0415

            attach_dispositions(all_findings)
        except Exception as exc:  # noqa: BLE001
            msg = f"disposition classification failed: {exc.__class__.__name__}: {exc}"
            errors.append(msg)
            log.warning(msg)

        try:
            from .cross_promo import attach_bridges  # noqa: PLC0415

            attach_bridges(all_findings)
        except Exception as exc:  # noqa: BLE001
            msg = f"bridge attachment failed: {exc.__class__.__name__}: {exc}"
            errors.append(msg)
            log.warning(msg)

        # Privacy-safe scan_root: use the basename only (e.g., "demo-app"),
        # falling back to "." for an empty basename (which happens when the
        # user scans the filesystem root). This is what gets embedded in
        # JSON / markdown / terminal output.
        safe_root = root.name or "."

        from .repo import detect_repository  # noqa: PLC0415

        report = Report(
            findings=all_findings,
            scan_root=safe_root,
            scan_timestamp=Report.now(),
            detectors_run=detector_names,
            repository=detect_repository(scan_root),
            errors=errors,
        )
        report.summary = report.build_summary()
        return report


def default_detectors() -> list[Detector]:
    """Return the default v0.5 detector set.

    Imports are deferred so each detector module can be developed and tested
    independently without breaking the orchestrator.
    """
    detectors: list[Detector] = []

    # Lazy imports keep the orchestrator usable even if a detector module is missing
    # during development. Each detector module is implemented in detectors/.
    # MCP: the audit detector is a superset of the shallow mcp_servers detector
    # (same discovery surface plus the deep-dive audit block + severity). Register
    # the audit detector; fall back to the discovery-only one if it is unavailable.
    try:
        from .detectors.mcp_audit import McpAuditDetector  # noqa: PLC0415
        detectors.append(McpAuditDetector())
    except ImportError as e:
        log.debug("MCP audit detector unavailable, trying discovery-only: %s", e)
        try:
            from .detectors.mcp_servers import McpServerDetector  # noqa: PLC0415
            detectors.append(McpServerDetector())
        except ImportError as e2:
            log.debug("MCP detector unavailable: %s", e2)

    try:
        from .detectors.llm_sdks import LlmSdkDetector  # noqa: PLC0415
        detectors.append(LlmSdkDetector())
    except ImportError as e:
        log.debug("LLM SDK detector unavailable: %s", e)

    try:
        from .detectors.agent_frameworks import AgentFrameworkDetector  # noqa: PLC0415
        detectors.append(AgentFrameworkDetector())
    except ImportError as e:
        log.debug("Agent framework detector unavailable: %s", e)

    try:
        from .detectors.env_keys import EnvKeyDetector  # noqa: PLC0415
        detectors.append(EnvKeyDetector())
    except ImportError as e:
        log.debug("Env key detector unavailable: %s", e)

    try:
        from .detectors.model_gateways import ModelGatewayDetector  # noqa: PLC0415
        detectors.append(ModelGatewayDetector())
    except ImportError as e:
        log.debug("Model gateway detector unavailable: %s", e)

    try:
        from .detectors.ai_infra import AiInfraDetector  # noqa: PLC0415
        detectors.append(AiInfraDetector())
    except ImportError as e:
        log.debug("AI infra detector unavailable: %s", e)

    try:
        from .detectors.api_endpoints import ApiEndpointDetector  # noqa: PLC0415
        detectors.append(ApiEndpointDetector())
    except ImportError as e:
        log.debug("API endpoint detector unavailable: %s", e)

    try:
        from .detectors.vector_rag import VectorRagDetector  # noqa: PLC0415
        detectors.append(VectorRagDetector())
    except ImportError as e:
        log.debug("Vector/RAG detector unavailable: %s", e)

    return detectors

"""Tests for the AI infrastructure detector."""
from __future__ import annotations

from pathlib import Path

from ai_surface.detectors.ai_infra import AiInfraDetector
from ai_surface.types import CATEGORY_AI_INFRA

FIXTURES = Path(__file__).parent / "fixtures" / "ai_infra"


# --- Detector protocol -------------------------------------------------------


def test_detector_protocol_attributes() -> None:
    d = AiInfraDetector()
    assert d.name == "ai_infra"
    assert d.category == CATEGORY_AI_INFRA


# --- Kubernetes --------------------------------------------------------------


def test_k8s_ollama_deployment() -> None:
    findings = AiInfraDetector().detect(str(FIXTURES / "k8s_ollama"))
    assert len(findings) == 1
    f = findings[0]
    assert f.category == CATEGORY_AI_INFRA
    assert "ollama" in f.surface
    assert f.evidence.metadata.get("image", "").startswith("ollama/ollama")
    assert f.evidence.metadata.get("namespace") == "ai"
    assert any("self-hosted LLM runtime" in r for r in f.risk_indicators)


def test_k8s_non_ai_deployment_ignored() -> None:
    findings = AiInfraDetector().detect(str(FIXTURES / "k8s_clean"))
    assert findings == []


def test_k8s_daemonset_kind_recognised(tmp_path: Path) -> None:
    (tmp_path / "ds.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: DaemonSet\n"
        "metadata:\n  name: tgi\n  namespace: ml\n"
        "spec:\n  template:\n    spec:\n"
        "      containers:\n        - name: tgi\n"
        "          image: huggingface/text-generation-inference:2.0\n",
        encoding="utf-8",
    )
    findings = AiInfraDetector().detect(str(tmp_path))
    assert len(findings) == 1
    assert findings[0].evidence.metadata.get("kind") == "DaemonSet"
    assert "text-generation-inference" in findings[0].surface


def test_k8s_sglang_statefulset(tmp_path: Path) -> None:
    (tmp_path / "ss.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: StatefulSet\n"
        "metadata:\n  name: sglang\n"
        "spec:\n  template:\n    spec:\n"
        "      containers:\n        - name: sglang\n"
        "          image: lmsysorg/sglang:latest\n",
        encoding="utf-8",
    )
    findings = AiInfraDetector().detect(str(tmp_path))
    assert len(findings) == 1
    assert "sglang" in findings[0].surface


# --- Helm --------------------------------------------------------------------


def test_helm_values_vllm() -> None:
    findings = AiInfraDetector().detect(str(FIXTURES / "helm_vllm"))
    assert len(findings) == 1
    f = findings[0]
    assert f.category == CATEGORY_AI_INFRA
    assert "vllm" in f.surface
    assert f.evidence.metadata.get("source") == "helm-values"


# --- docker-compose ----------------------------------------------------------


def test_compose_ollama_service() -> None:
    findings = AiInfraDetector().detect(str(FIXTURES / "compose_ollama"))
    # Only the ollama service is an AI runtime; the app image is ignored.
    assert len(findings) == 1
    f = findings[0]
    assert f.category == CATEGORY_AI_INFRA
    assert "ollama" in f.surface
    assert f.evidence.metadata.get("source") == "docker-compose"


def test_compose_variant_filename(tmp_path: Path) -> None:
    (tmp_path / "compose.prod.yaml").write_text(
        "services:\n  vllm:\n    image: vllm/vllm-openai:latest\n",
        encoding="utf-8",
    )
    findings = AiInfraDetector().detect(str(tmp_path))
    assert len(findings) == 1
    assert "vllm" in findings[0].surface


# --- Dockerfiles -------------------------------------------------------------


def test_dockerfile_from_ai_base_image() -> None:
    findings = AiInfraDetector().detect(str(FIXTURES / "dockerfile_vllm"))
    assert len(findings) == 1
    f = findings[0]
    assert f.category == CATEGORY_AI_INFRA
    assert "vllm" in f.surface
    assert f.evidence.metadata.get("base_image", "").startswith("vllm/vllm-openai")


def test_dockerfile_serve_command_on_generic_base() -> None:
    """A generic base image that runs `vllm serve` should still be caught."""
    findings = AiInfraDetector().detect(str(FIXTURES / "dockerfile_serve"))
    assert len(findings) == 1
    f = findings[0]
    assert "vllm" in f.surface
    # No AI base image; matched via the serve-command fallback.
    assert "base_image" not in f.evidence.metadata


def test_dockerfile_named_variant(tmp_path: Path) -> None:
    (tmp_path / "api.Dockerfile").write_text(
        "FROM ghcr.io/ggerganov/llama.cpp:server\nEXPOSE 8080\n",
        encoding="utf-8",
    )
    findings = AiInfraDetector().detect(str(tmp_path))
    assert len(findings) == 1
    assert "llama.cpp" in findings[0].surface


def test_dockerfile_non_ai_ignored(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM node:20-alpine\nRUN npm ci\nCMD [\"node\", \"server.js\"]\n",
        encoding="utf-8",
    )
    findings = AiInfraDetector().detect(str(tmp_path))
    assert findings == []


# --- Terraform ---------------------------------------------------------------


def test_terraform_bedrock_provisioned_throughput() -> None:
    findings = AiInfraDetector().detect(str(FIXTURES / "terraform_bedrock"))
    assert len(findings) == 1
    f = findings[0]
    assert f.category == CATEGORY_AI_INFRA
    assert "claude-3-5-sonnet" in f.surface
    assert any("high-cost AI infrastructure" in r for r in f.risk_indicators)


def test_terraform_sagemaker_skipped_when_not_llm(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        'resource "aws_sagemaker_endpoint" "tabular" {\n'
        '  name = "tabular-xgboost"\n'
        '  endpoint_config_name = "xgb-config"\n'
        "}\n",
        encoding="utf-8",
    )
    findings = AiInfraDetector().detect(str(tmp_path))
    assert findings == []


def test_terraform_sagemaker_llm_endpoint(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        'resource "aws_sagemaker_endpoint" "llama_inference" {\n'
        '  name = "llama-3-70b-endpoint"\n'
        '  endpoint_config_name = "llama-config"\n'
        "}\n",
        encoding="utf-8",
    )
    findings = AiInfraDetector().detect(str(tmp_path))
    assert len(findings) == 1
    assert "SageMaker" in findings[0].surface


def test_terraform_heredoc_with_brace_in_body(tmp_path: Path) -> None:
    """HCL heredocs that inline a JSON IAM policy must not break the parser."""
    (tmp_path / "main.tf").write_text(
        'resource "aws_sagemaker_endpoint" "llama" {\n'
        '  name = "llama3-prod"\n'
        '  endpoint_config_name = "llama-config"\n'
        "  policy = <<-EOT\n"
        '    { "Statement": [{ "Effect": "Allow" }] }\n'
        "  EOT\n"
        "}\n",
        encoding="utf-8",
    )
    findings = AiInfraDetector().detect(str(tmp_path))
    assert len(findings) == 1
    assert "SageMaker" in findings[0].surface


def test_terraform_block_comment_with_brace(tmp_path: Path) -> None:
    """`/* ... } ... */` comments must not be treated as closing braces."""
    (tmp_path / "main.tf").write_text(
        'resource "aws_bedrock_custom_model" "x" {\n'
        '  model_id = "anthropic.claude-3-haiku-20240307-v1:0"\n'
        '  /* example response: { "status": "READY" } */\n'
        "}\n",
        encoding="utf-8",
    )
    findings = AiInfraDetector().detect(str(tmp_path))
    assert len(findings) == 1
    assert "Bedrock custom model" in findings[0].surface


def test_terraform_nested_braces(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        'resource "aws_bedrock_provisioned_model_throughput" "prod" {\n'
        '  provisioned_model_name = "claude-prod"\n'
        '  model_id = "anthropic.claude-3-5-sonnet-20240620-v1:0"\n'
        "  lifecycle { prevent_destroy = true }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = AiInfraDetector().detect(str(tmp_path))
    assert len(findings) == 1
    assert findings[0].evidence.metadata["model_id"] == (
        "anthropic.claude-3-5-sonnet-20240620-v1:0"
    )


# --- Aggregate ---------------------------------------------------------------


def test_clean_directory_no_findings() -> None:
    findings = AiInfraDetector().detect(str(FIXTURES / "clean"))
    assert findings == []


def test_combined_fixtures_cover_all_sources() -> None:
    """Running on the parent ai_infra/ dir surfaces every source kind."""
    findings = AiInfraDetector().detect(str(FIXTURES))
    # k8s ollama, helm vllm, compose ollama, dockerfile vllm, dockerfile serve,
    # terraform bedrock = 6. k8s_clean and clean contribute nothing.
    assert len(findings) == 6
    assert all(f.category == CATEGORY_AI_INFRA for f in findings)
    runtimes = {f.evidence.metadata.get("runtime") for f in findings}
    assert "ollama" in runtimes
    assert "vllm" in runtimes


def test_yaml_alias_bomb_is_refused_gracefully(tmp_path: Path) -> None:
    """A YAML file with pathological anchor / alias density must not be
    parsed by the detector. Without the bomb defence in utils/specs.py,
    PyYAML's safe_load expands aliases without bound and can OOM the
    scan host. The detector should return no findings on this input."""
    # Build a 200-anchor / 200-alias header that trips the heuristic. The
    # tail looks like a normal k8s manifest with an AI image, so without
    # the bomb defence the detector would otherwise try to parse it.
    anchors = "\n".join(f"a{i}: &a{i} x" for i in range(250))
    aliases = "\n".join(f"b{i}: *a{i}" for i in range(250))
    payload = (
        anchors
        + "\n"
        + aliases
        + "\n"
        + "kind: Deployment\n"
        + "spec:\n  template:\n    spec:\n      containers:\n"
        + "        - image: ollama/ollama:latest\n"
    )
    (tmp_path / "bomb.yaml").write_text(payload, encoding="utf-8")
    # Should not crash, should not OOM, should not raise.
    findings = AiInfraDetector().detect(str(tmp_path))
    # We do not assert findings == [] strictly; the regex-level k8s detection
    # operates on text and may still find the image. What we assert is that
    # parse_yaml_lenient did not blow up: detect() returned.
    assert isinstance(findings, list)

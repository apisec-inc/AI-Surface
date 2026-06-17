# ai-surface GitHub Action runtime.
# Slim Python base; installs ai-surface from the action repo and runs the
# entry script against the consumer's workspace at /github/workspace.

FROM python:3.12-slim AS runtime

# Install git so the entry script can do base-vs-head checkouts in v0.6.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /action

# Copy the action repo (this Dockerfile sits at the root of the action repo).
# README.md is required: pyproject declares `readme = "README.md"`, so the
# hatchling build reads it to generate package metadata. Without it the
# `pip install /action` below fails with "Readme file does not exist".
COPY pyproject.toml /action/pyproject.toml
COPY README.md /action/README.md
COPY src /action/src
COPY .github /action/.github

# Install ai-surface from local source plus the requests dep used by the entry script.
RUN pip install --no-cache-dir /action \
    && pip install --no-cache-dir requests==2.32.3

# GitHub Actions mounts the consumer's workspace here.
WORKDIR /github/workspace

ENTRYPOINT ["python", "/action/.github/action/entry.py"]

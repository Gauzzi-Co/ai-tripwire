"""Keep integration tests away from workstation logs, cron and Git credentials."""

import os

import pytest


@pytest.fixture(autouse=True)
def isolated_host_tools(tmp_path, monkeypatch):
    bin_dir = tmp_path / "test-bin"
    bin_dir.mkdir()
    for name in ("logger", "crontab"):
        stub = bin_dir / name
        stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        stub.chmod(0o700)
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")

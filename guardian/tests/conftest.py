from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import pytest


_LOCAL_TMP = Path(__file__).resolve().parents[1] / ".pytest-tmp"


def pytest_configure() -> None:
    """
    Force pytest/tempfile usage into a repo-local temp directory.

    The default Windows temp location is not writable in this execution
    environment, which causes unrelated test failures when fixtures create
    temporary files or directories.
    """
    if _LOCAL_TMP.exists():
        shutil.rmtree(_LOCAL_TMP, ignore_errors=True)
    _LOCAL_TMP.mkdir(parents=True, exist_ok=True)

    local_tmp_str = str(_LOCAL_TMP)
    os.environ["TMPDIR"] = local_tmp_str
    os.environ["TEMP"] = local_tmp_str
    os.environ["TMP"] = local_tmp_str
    tempfile.tempdir = local_tmp_str

    class _WorkspaceTemporaryDirectory:
        def __init__(self, suffix: str | None = None, prefix: str | None = None, dir: str | None = None):
            self.name = tempfile.mkdtemp(
                suffix=suffix or "",
                prefix=prefix or "tmp",
                dir=dir or local_tmp_str,
            )

        def __enter__(self) -> str:
            return self.name

        def __exit__(self, exc_type, exc, tb) -> None:
            shutil.rmtree(self.name, ignore_errors=True)
            return False

        def cleanup(self) -> None:
            shutil.rmtree(self.name, ignore_errors=True)

    tempfile.TemporaryDirectory = _WorkspaceTemporaryDirectory


@pytest.fixture
def tmp_path() -> Path:
    path = Path(tempfile.mkdtemp(prefix="pytest-", dir=str(_LOCAL_TMP)))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)

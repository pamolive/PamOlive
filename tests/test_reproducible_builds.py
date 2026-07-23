from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_runtime_dockerfile_uses_hash_locked_dependencies():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "COPY pyproject.toml uv.lock" in dockerfile
    assert "uv sync --frozen" in dockerfile
    assert "pip install ." not in dockerfile
    assert "pip install --upgrade pip" not in dockerfile


def test_uv_lock_is_present():
    lockfile = ROOT / "uv.lock"
    assert lockfile.exists()
    content = lockfile.read_text(encoding="utf-8")

    assert content.startswith("version = ")
    assert "[[package]]" in content
    assert 'name = "pam-olive"' in content

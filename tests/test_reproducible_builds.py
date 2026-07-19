from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_runtime_dockerfile_uses_hash_locked_dependencies():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "COPY requirements.lock ./" in dockerfile
    assert "pip install --require-hashes -r requirements.lock" in dockerfile
    assert "pip install ." not in dockerfile
    assert "pip install --upgrade pip" not in dockerfile


def test_requirements_lock_is_hash_pinned():
    lockfile = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    package_lines = [
        line
        for line in lockfile.splitlines()
        if line and not line.startswith((" ", "#")) and "==" in line
    ]

    assert "uv pip compile" in lockfile
    assert package_lines
    assert "--hash=sha256:" in lockfile
    for line in package_lines:
        package_name = line.split("==", 1)[0]
        package_block_start = lockfile.index(line)
        next_package_start = min(
            [
                lockfile.find(f"\n{name}==", package_block_start + len(line))
                for name in (pkg.split("==", 1)[0] for pkg in package_lines)
                if lockfile.find(f"\n{name}==", package_block_start + len(line)) != -1
            ]
            or [len(lockfile)]
        )
        package_block = lockfile[package_block_start:next_package_start]
        assert "--hash=sha256:" in package_block, f"{package_name} is not hash pinned"
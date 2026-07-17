import importlib.util
from pathlib import Path


def load_rate_limiter():
    path = Path(__file__).parents[1] / "keyring" / "rate_limit.py"
    spec = importlib.util.spec_from_file_location("pamolive_keyring_rate_limit", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.SlidingWindowRateLimiter


def test_keyring_rate_limit_is_per_operation_and_recovers_after_window():
    now = [100.0]
    limiter = load_rate_limiter()(
        {"default": 2, "/decrypt": 1},
        window_seconds=60,
        clock=lambda: now[0],
    )

    assert limiter.acquire("/decrypt") == (True, 0)
    assert limiter.acquire("/decrypt") == (False, 60)
    assert limiter.acquire("/encrypt") == (True, 0)
    assert limiter.acquire("/encrypt") == (True, 0)
    assert limiter.acquire("/encrypt") == (False, 60)

    now[0] = 160.1
    assert limiter.acquire("/decrypt") == (True, 0)


def test_keyring_app_wires_rate_limit_to_every_sensitive_operation():
    app_source = (Path(__file__).parents[1] / "keyring" / "app.py").read_text()

    for route in ("encrypt", "decrypt", "sign", "verify"):
        assert f'@app.post("/{route}", dependencies=PROTECTED_OPERATION)' in app_source
    assert 'headers={"Retry-After": str(retry_after)}' in app_source

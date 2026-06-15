from __future__ import annotations


def rust_core_available() -> bool:
    try:
        import appsec_core  # type: ignore
    except ImportError:
        return False
    return True


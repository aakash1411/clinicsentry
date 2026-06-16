"""Real-SDK adapter compatibility tests.

Each test in this package compiles against a real framework SDK and verifies
that our adapter's monkey-patching / callback registration does not crash. The
tests skip cleanly when the SDK is not installed.

Mark: ``@pytest.mark.adapter`` (declared in pyproject.toml).
"""

import pytest


@pytest.fixture(autouse=True)
def reachable_manager(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stand in for a reachable Wazuh manager in every test.

    The CLI refuses to run without one, and most tests exercise its plumbing
    rather than the replay itself. They get a manager that answers and replays
    nothing; a test about the manager check or the replay patches these again.
    """

    from wazuhcoverage import cli

    monkeypatch.setattr(cli, "unavailable_reason", lambda: None)
    monkeypatch.setattr(cli, "verify_findings", lambda *_args, **_kwargs: ())

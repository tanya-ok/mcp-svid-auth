"""Google setup must not dismantle the active viewer's private identity tunnel."""

from __future__ import annotations

import contextlib
from unittest.mock import Mock

import pytest

from scripts import kubernetes_ui as ui
from scripts import run_google_setup_demo as setup
from scripts import zitadel_demo as identity
from scripts.lab_runtime import DemoRuntimeError


def test_setup_borrows_only_a_verified_viewer_tunnel(monkeypatch: pytest.MonkeyPatch) -> None:
    lock = Mock(return_value=contextlib.nullcontext())
    verify = Mock(return_value=True)
    own_connection = Mock()
    monkeypatch.setattr(ui, "launch_lock", lock)
    monkeypatch.setattr(ui, "running", verify)
    monkeypatch.setattr(identity, "connection", own_connection)
    with setup.setup_connection():
        verify.assert_called_once_with()
        lock.assert_called_once_with()
    own_connection.assert_not_called()


def test_setup_owns_its_connection_when_no_viewer_exists(monkeypatch: pytest.MonkeyPatch) -> None:
    own_connection = Mock(return_value=contextlib.nullcontext())
    monkeypatch.setattr(ui, "launch_lock", contextlib.nullcontext)
    monkeypatch.setattr(ui, "running", Mock(return_value=False))
    monkeypatch.setattr(identity, "connection", own_connection)
    with setup.setup_connection():
        own_connection.assert_called_once_with()


def test_unverified_session_refuses_before_any_forwarder_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    own_connection = Mock()
    monkeypatch.setattr(ui, "launch_lock", contextlib.nullcontext)
    monkeypatch.setattr(
        ui, "running", Mock(side_effect=DemoRuntimeError("UI session could not be verified"))
    )
    monkeypatch.setattr(identity, "connection", own_connection)
    with pytest.raises(DemoRuntimeError, match="could not be verified"), setup.setup_connection():
        pytest.fail("An unverified session must not be borrowed")
    own_connection.assert_not_called()

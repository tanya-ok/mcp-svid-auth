"""An isolated human identity profile cannot dismantle the shared lab."""

from __future__ import annotations

import subprocess
import sys
from unittest.mock import Mock

import pytest

from scripts import kubernetes_demo as lab
from scripts.lab_runtime import DemoRuntimeError


def test_isolated_teardown_refuses_before_any_cluster_call(monkeypatch: pytest.MonkeyPatch) -> None:
    probe = Mock()
    monkeypatch.setattr(lab, "ISOLATED", True)
    monkeypatch.setattr(lab, "kube", probe)
    with pytest.raises(DemoRuntimeError, match="cannot remove shared workloads"):
        lab.down()
    probe.assert_not_called()


@pytest.mark.parametrize("operation", ["runtime-stop", "up", "down", "build"])
def test_isolated_cli_refuses_shared_mutations(
    operation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    probe = Mock()
    monkeypatch.setattr(lab, "ISOLATED", True)
    monkeypatch.setattr(lab, "verify_instance", probe)
    monkeypatch.setattr(sys, "argv", ["lab", operation])
    with pytest.raises(SystemExit) as error:
        lab.main()
    assert error.value.code == 1
    probe.assert_not_called()


def test_isolated_profile_does_not_create_another_vm(monkeypatch: pytest.MonkeyPatch) -> None:
    probe = Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(lab, "ISOLATED", True)
    monkeypatch.setattr(lab, "lima", probe)
    with pytest.raises(DemoRuntimeError, match="existing shared lab VM"):
        lab.runtime_up()
    assert probe.call_count == 1
    assert probe.call_args.args[0][0] == "list"

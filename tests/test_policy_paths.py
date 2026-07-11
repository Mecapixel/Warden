"""
tests/test_policy_paths.py

Regression pins for the Windows policy-generation bug found in the field
(v1.5.4-era, Windows / Python 3.14): the CLI's generated policies embedded
OS-native paths in DOUBLE-quoted YAML scalars. In double-quoted YAML, a
backslash starts an escape sequence — so 'C:\\Users\\...' produced
"expected escape sequence of 8 hexadecimal numbers" and Warden's own
default policy was unreadable on Windows. Contract pinned here:

  * Both generated policy templates must parse as YAML no matter what
    OS-native path is substituted in — including backslashes, spaces,
    and drive letters.
  * A policy file that is NOT valid YAML must surface as a clear
    PolicyValidationError, never a raw yaml scanner traceback.
  * `warden stats --audit <path>` must not touch, load, or depend on any
    policy file at all — telemetry over an explicit log stands alone,
    even with a corrupt policy sitting in the working directory.
"""

import yaml
import pytest

from proxy.audit.log import AuditLog
from proxy.cli import _DENY_ALL_POLICY, _STARTER_POLICY, build_parser
from proxy.policy.engine import PolicyEngine, PolicyValidationError


WINDOWS_STYLE_PATHS = [
    ("C:\\Users\\mecad\\Desktop\\The Blueprint\\Warden\\workspace",
     "C:\\Users\\mecad\\Desktop\\The Blueprint\\Warden\\audit\\warden_audit.db"),
    ("C:\\Users\\name with spaces\\ws", "C:\\temp\\a.db"),
    ("/plain/posix/workspace", "/plain/posix/audit.db"),
]


class TestGeneratedPoliciesSurviveAnyPath:
    @pytest.mark.parametrize("workspace,audit", WINDOWS_STYLE_PATHS)
    def test_deny_all_template_parses(self, workspace, audit):
        text = _DENY_ALL_POLICY.format(workspace=workspace, audit=audit)
        loaded = yaml.safe_load(text)  # the exact call that broke on Windows
        assert loaded["workspace_root"] == workspace
        assert loaded["audit"]["path"] == audit

    @pytest.mark.parametrize("workspace,audit", WINDOWS_STYLE_PATHS)
    def test_starter_template_parses(self, workspace, audit):
        text = _STARTER_POLICY.format(workspace=workspace, audit=audit)
        loaded = yaml.safe_load(text)
        assert loaded["workspace_root"] == workspace


class TestInvalidYamlFailsLoud:
    def test_unparseable_policy_is_a_policy_validation_error(self, tmp_path):
        bad = tmp_path / "broken.yaml"
        # The exact Windows failure shape: \U escape in a double-quoted scalar.
        bad.write_text('version: 1\nworkspace_root: "C:\\Users\\broken"\n')
        with pytest.raises(PolicyValidationError, match="not valid YAML"):
            PolicyEngine(str(bad))


class TestStatsIndependentOfPolicy:
    def test_stats_with_explicit_audit_ignores_corrupt_policy(
            self, tmp_path, monkeypatch, capsys):
        # A corrupt generated policy sits in the working directory — the
        # field condition. stats --audit must not even open it.
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".warden.default.policy.yaml").write_text(
            'version: 1\nworkspace_root: "C:\\Users\\broken"\n')

        db = tmp_path / "t.db"
        log = AuditLog(str(db))
        log.record("read_file", "allow", "ok", {"rule": "TOOL-004", "risk": 0})
        log.close()

        args = build_parser().parse_args(["stats", "--audit", str(db), "--json"])
        assert args.func(args) == 0
        assert '"total_events": 1' in capsys.readouterr().out

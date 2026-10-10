"""Unit and integration tests for Basebreak CLI and developer workflow.

P-19.01 - P-19.05:
- CLI argument parsing and commands
- Config schema, safe defaults, zero-cost rules
- Run persistence under .basebreak/runs/<run_id>/
- Clear BLOCKED / INCONCLUSIVE / CONTRADICTED UX and exit codes (0, 1, 2)
- Secret redaction in console and file outputs
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from basebreak.cli.config import BasebreakConfig, ConfigValidationError
from basebreak.cli.main import main
from basebreak.cli.persistence import (
    RunNotFoundError,
    RunPersistenceManager,
)
from basebreak.cli.runner import execute_verification_pipeline
from basebreak.verifier.witness_result import WitnessOutcome


class TestCliConfig:
    """Tests for P-19.03: Config schema and safe defaults."""

    def test_safe_defaults(self) -> None:
        cfg = BasebreakConfig()
        assert cfg.offline_mode is True
        assert cfg.zero_cost_mode is True
        assert cfg.allow_live is False
        assert cfg.sandbox_provider == "local"
        assert cfg.token_factory_promo_stop_threshold == 5.0
        assert cfg.runs_dir == ".basebreak/runs"
        assert cfg.default_format == "text"

    def test_config_validation_invalid_provider(self) -> None:
        with pytest.raises(ConfigValidationError, match="Invalid sandbox_provider"):
            BasebreakConfig(sandbox_provider="unsupported_cloud")

    def test_config_validation_negative_threshold(self) -> None:
        with pytest.raises(ConfigValidationError, match="cannot be negative"):
            BasebreakConfig(token_factory_promo_stop_threshold=-1.0)

    def test_config_from_file(self, tmp_path: Path) -> None:
        config_file = tmp_path / "test_config.json"
        config_file.write_text(
            json.dumps({"sandbox_provider": "mock", "token_factory_promo_stop_threshold": 10.0}),
            encoding="utf-8",
        )
        loaded = BasebreakConfig.from_file(config_file)
        assert loaded.sandbox_provider == "mock"
        assert loaded.token_factory_promo_stop_threshold == 10.0

    def test_config_secret_redaction(self) -> None:
        cfg = BasebreakConfig(api_endpoint="https://user:ghp_SuperSecretToken1234567890@api.host.com")
        safe_dict = cfg.to_safe_dict()
        assert "ghp_" not in safe_dict["api_endpoint"]
        assert "[REDACTED]" in safe_dict["api_endpoint"]


class TestCliPersistence:
    """Tests for run state persistence under .basebreak/runs/<run_id>/."""

    def test_save_and_load_run(self, tmp_path: Path) -> None:
        mgr = RunPersistenceManager(tmp_path)
        run_id = "run_test_001"
        metadata = {"run_id": run_id, "status": "VERIFIED", "exit_code": 0}
        evidence = [{"world": "BASE", "fact": {"outcome": "FAIL"}}]
        receipt = {"task_id": "task_1", "schema_version": "1.0.0"}

        mgr.save_run(run_id, metadata, evidence, receipt)

        assert mgr.run_exists(run_id) is True
        loaded_meta = mgr.load_metadata(run_id)
        assert loaded_meta["status"] == "VERIFIED"
        assert loaded_meta["exit_code"] == 0

        loaded_ev = mgr.load_evidence(run_id)
        assert len(loaded_ev) == 1
        assert loaded_ev[0]["world"] == "BASE"

        loaded_rc = mgr.load_receipt(run_id)
        assert loaded_rc is not None
        assert loaded_rc["task_id"] == "task_1"

        runs = mgr.list_runs()
        assert run_id in runs

    def test_load_nonexistent_run_raises(self, tmp_path: Path) -> None:
        mgr = RunPersistenceManager(tmp_path)
        with pytest.raises(RunNotFoundError):
            mgr.load_metadata("missing_run")


class TestCliExecutionPipeline:
    """Tests for P-19.01 - P-19.04 verification pipeline and exit codes."""

    def test_verify_happy_path_verified(self, tmp_path: Path) -> None:
        cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
        res = execute_verification_pipeline(
            target="test_repo",
            base_sha="1" * 40,
            config=cfg,
            base_outcome_override=WitnessOutcome.FAIL,
            candidate_outcome_override=WitnessOutcome.PASS,
            cf_outcome_override=WitnessOutcome.FAIL,
        )
        assert res.status == "VERIFIED"
        assert res.exit_code == 0
        assert res.receipt is not None
        assert "If the patch matters, the base must break." in res.thesis

    def test_verify_base_pass_contradicted(self, tmp_path: Path) -> None:
        cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
        res = execute_verification_pipeline(
            target="test_repo",
            base_sha="1" * 40,
            config=cfg,
            base_outcome_override=WitnessOutcome.PASS,  # Base already passed
            candidate_outcome_override=WitnessOutcome.PASS,
            cf_outcome_override=WitnessOutcome.FAIL,
        )
        assert res.status == "CONTRADICTED"
        assert res.exit_code == 1

    def test_verify_candidate_fail_contradicted(self, tmp_path: Path) -> None:
        cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
        res = execute_verification_pipeline(
            target="test_repo",
            base_sha="1" * 40,
            config=cfg,
            base_outcome_override=WitnessOutcome.FAIL,
            candidate_outcome_override=WitnessOutcome.FAIL,  # Candidate failed
            cf_outcome_override=WitnessOutcome.FAIL,
        )
        assert res.status == "CONTRADICTED"
        assert res.exit_code == 1

    def test_verify_counterfactual_pass_contradicted(self, tmp_path: Path) -> None:
        cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
        res = execute_verification_pipeline(
            target="test_repo",
            base_sha="1" * 40,
            config=cfg,
            base_outcome_override=WitnessOutcome.FAIL,
            candidate_outcome_override=WitnessOutcome.PASS,
            cf_outcome_override=WitnessOutcome.PASS,  # Counterfactual passed
        )
        assert res.status == "CONTRADICTED"
        assert res.exit_code == 1

    def test_verify_empty_patch_contradicted(self, tmp_path: Path) -> None:
        cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
        res = execute_verification_pipeline(
            target="test_repo",
            patch="",  # Empty patch
            config=cfg,
        )
        assert res.status == "CONTRADICTED"
        assert res.exit_code == 1

    def test_verify_allow_live_blocked_safely(self, tmp_path: Path) -> None:
        cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
        res = execute_verification_pipeline(
            target="test_repo",
            allow_live=True,  # Live requested without verified budget
            config=cfg,
        )
        assert res.status == "BLOCKED"
        assert res.exit_code == 2
        assert "Zero-Cost Law" in res.message

    def test_verify_missing_target_invalid_input(self, tmp_path: Path) -> None:
        cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
        res = execute_verification_pipeline(
            target="",
            config=cfg,
        )
        assert res.status == "INVALID_INPUT"
        assert res.exit_code == 2


class TestCliCommandsInvocation:
    """Full CLI invocation via main(argv)."""

    def test_cli_version(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0
        captured = capsys.readouterr()
        assert "basebreak 0.1.0" in captured.out

    def test_cli_config(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["config"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "BASEBREAK EFFECTIVE CONFIGURATION" in captured.out
        assert "Offline Mode:        True" in captured.out

    def test_cli_verify_and_status_and_receipt_flow(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runs_dir = str(tmp_path / "runs")

        # 1. Run verify
        verify_code = main([
            "--runs-dir",
            runs_dir,
            "verify",
            "dummy_repo",
            "--base-sha",
            "1" * 40,
        ])
        assert verify_code == 0
        captured = capsys.readouterr()
        assert "[VERIFIED]" in captured.out
        assert "Thesis: If the patch matters, the base must break." in captured.out

        # Extract run_id from output
        lines = captured.out.splitlines()
        run_id_line = next(line for line in lines if "Run ID:" in line)
        run_id = run_id_line.split("Run ID:")[1].strip()

        # 2. Run status
        status_code = main([
            "--runs-dir",
            runs_dir,
            "status",
            run_id,
        ])
        assert status_code == 0
        status_out = capsys.readouterr().out
        assert f"BASEBREAK RUN STATUS: {run_id}" in status_out
        assert "[VERIFIED]" in status_out

        # 3. Run evidence
        ev_code = main([
            "--runs-dir",
            runs_dir,
            "evidence",
            run_id,
        ])
        assert ev_code == 0
        ev_out = capsys.readouterr().out
        assert "EVIDENCE RECORDS FOR RUN:" in ev_out
        assert "World: BASE" in ev_out
        assert "World: CANDIDATE" in ev_out

        # 4. Run receipt
        rc_code = main([
            "--runs-dir",
            runs_dir,
            "receipt",
            run_id,
        ])
        assert rc_code == 0
        rc_out = capsys.readouterr().out
        assert "BASEBREAK CAUSAL VERIFICATION RECEIPT" in rc_out
        assert "Causal Coverage: 100.0%" in rc_out

    def test_cli_secret_redaction_in_output(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Check that secret patterns are scrubbed from outputs
        runs_dir = str(tmp_path / "runs")
        secret_token = "ghp_123456789012345678901234567890123456"
        secret_target = f"repo/{secret_token}"

        main([
            "--runs-dir",
            runs_dir,
            "verify",
            secret_target,
            "--base-sha",
            "1" * 40,
        ])
        out = capsys.readouterr().out
        assert secret_token not in out
        assert "[REDACTED]" in out

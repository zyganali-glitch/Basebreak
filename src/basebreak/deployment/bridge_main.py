"""Windows-compatible localhost runner for the trusted verifier bridge (P-27.06).

Minimal operational entrypoint. It constructs the *existing* trusted bridge from
environment configuration (``create_trusted_verifier_bridge_from_env``) and serves
it through the *existing* stdlib server (``BasebreakLiveBridgeServer``). No bridge
execution, verification, signing, or admission logic is duplicated here.

Safety properties:

- Binds **strictly to the loopback interface** (``127.0.0.1``); never ``0.0.0.0``
  or an external network interface.
- Never enables live execution. The runtime live switch remains driven solely by
  the operator's environment configuration.
- Never prints credential, secret, or environment-variable values.
- Never creates temporary production idempotency storage; if no durable state
  directory is configured the bridge stays fail-closed.
- Provides an offline ``--check`` self-check that reports configuration readiness
  as booleans only and neither starts a server nor contacts any provider.

Usage::

    python -m basebreak.deployment.bridge_main --check
    python -m basebreak.deployment.bridge_main --port 8787
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
import time
from collections.abc import Iterator, Sequence
from typing import Any

from basebreak.deployment.live_bridge import (
    LIVE_BRIDGE_ROUTE,
    BasebreakLiveBridgeServer,
    TrustedVerifierBridge,
    _signer_matches_canonical_authority,
    create_trusted_verifier_bridge_from_env,
)

# Strict loopback binding. This is intentionally not configurable to prevent an
# operator (or a mistyped flag) from exposing the private bridge on an external
# interface.
LOOPBACK_HOST: str = "127.0.0.1"
DEFAULT_BRIDGE_PORT: int = 8787
MIN_PORT: int = 1
MAX_PORT: int = 65535


class BridgeRunnerError(Exception):
    """Raised when the bridge runner is asked to start in an invalid state."""


def validate_port(value: Any) -> int:
    """Validate and normalize a TCP port for the local bridge.

    Accepts an integer or a base-10 digit string. Rejects booleans, floats,
    non-numeric strings, and values outside ``1..65535``.
    """
    if isinstance(value, bool):
        raise ValueError(f"Port must be an integer, got {value!r}.")
    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and value.strip().isdigit():
        port = int(value.strip())
    else:
        raise ValueError(f"Port must be an integer, got {value!r}.")
    if port < MIN_PORT or port > MAX_PORT:
        raise ValueError(f"Port must be between {MIN_PORT} and {MAX_PORT}, got {port}.")
    return port


def _cli_port(value: str) -> int:
    try:
        return validate_port(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _ensure_loopback(host: str) -> None:
    if host != LOOPBACK_HOST:
        raise BridgeRunnerError(
            f"Refusing to bind to {host!r}; the bridge may only bind to {LOOPBACK_HOST}."
        )


def collect_readiness(bridge: TrustedVerifierBridge) -> dict[str, Any]:
    """Return a secret-free readiness report for the configured bridge.

    Reports only booleans and non-sensitive configuration labels. It never
    includes secret values, credential contents, or environment variables.
    """
    config = bridge.config
    signer = bridge.signer
    signing_present = signer is not None
    signing_compatible = bool(signing_present and _signer_matches_canonical_authority(signer))
    provider_credentials_present = bool(config.nebius_api_key and config.nebius_project_id)
    durable_state_configured = bool(config.bridge_state_dir)
    idempotency_available = bridge.idempotency_store is not None

    ready_for_live = bool(
        config.live_execution_enabled
        and config.shared_secret
        and provider_credentials_present
        and signing_compatible
        and bridge.executor is not None
        and bridge.execution_authority_verifier is not None
        and durable_state_configured
        and idempotency_available
    )

    return {
        "bind_host": LOOPBACK_HOST,
        "route": config.route_path or LIVE_BRIDGE_ROUTE,
        "live_execution_enabled": bool(config.live_execution_enabled),
        "shared_secret_configured": bool(config.shared_secret),
        "provider_credentials_present": provider_credentials_present,
        "signing_authority_present": signing_present,
        "signing_authority_compatible": signing_compatible,
        "executor_configured": bridge.executor is not None,
        "execution_authority_verifier_configured": bridge.execution_authority_verifier is not None,
        "durable_idempotency_state_configured": durable_state_configured,
        "durable_idempotency_available": idempotency_available,
        "expected_source_commit_configured": bool(str(config.expected_source_commit or "").strip()),
        "expected_target": config.expected_target,
        "ready_for_live": ready_for_live,
    }


@contextlib.contextmanager
def bridge_server(bridge: TrustedVerifierBridge, port: int) -> Iterator[BasebreakLiveBridgeServer]:
    """Start the bridge on loopback and stop it deterministically on exit."""
    _ensure_loopback(LOOPBACK_HOST)
    server = BasebreakLiveBridgeServer(bridge=bridge, host=LOOPBACK_HOST, port=port)
    server.start()
    try:
        yield server
    finally:
        server.stop()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m basebreak.deployment.bridge_main",
        description=(
            "Run the trusted verifier bridge on loopback (127.0.0.1). "
            "Fail-closed: live execution stays disabled unless the operator has "
            "explicitly configured it."
        ),
    )
    parser.add_argument(
        "--port",
        type=_cli_port,
        default=DEFAULT_BRIDGE_PORT,
        help=f"Local TCP port to bind on {LOOPBACK_HOST} (default: {DEFAULT_BRIDGE_PORT}).",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Print a secret-free configuration readiness report and exit. "
            "Does not start a server or contact any provider."
        ),
    )
    return parser


def _cmd_check() -> int:
    bridge = create_trusted_verifier_bridge_from_env()
    readiness = collect_readiness(bridge)
    sys.stdout.write(json.dumps(readiness, indent=2, sort_keys=True) + "\n")
    return 0


def _cmd_serve(port: int) -> int:
    bridge = create_trusted_verifier_bridge_from_env()
    readiness = collect_readiness(bridge)

    try:
        with bridge_server(bridge, port) as server:
            sys.stdout.write(
                json.dumps(
                    {
                        "bridge_url": server.base_url,
                        "route": readiness["route"],
                        "readiness": readiness,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )
            sys.stdout.flush()
            try:
                while True:
                    time.sleep(1.0)
            except KeyboardInterrupt:
                sys.stdout.write("Shutting down bridge...\n")
    except OSError as exc:
        sys.stderr.write(f"Unable to start bridge on {LOOPBACK_HOST}:{port}: {exc}\n")
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.check:
        return _cmd_check()
    return _cmd_serve(validate_port(args.port))


if __name__ == "__main__":
    raise SystemExit(main())

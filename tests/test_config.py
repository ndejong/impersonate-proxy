"""Unit tests for command line arguments and environment variables configuration parsing."""

import os
from unittest.mock import patch

import pytest

from impersonate_proxy import main as impersonate_proxy

_DEFAULT_RUN_CALL: dict[str, object] = {
    "host": "127.0.0.1",
    "port": 8899,
    "impersonate": "chrome",
    "ca_dir": None,
    "header_mode": "enrich",
    "strip_client_leak_headers": False,
    "debug": False,
    "quiet": False,
}


def test_config_defaults():
    """Test defaults when no CLI args or env vars are set."""
    with (
        patch("sys.argv", ["impersonate-proxy"]),
        patch.dict(os.environ, {}, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once_with(**_DEFAULT_RUN_CALL)


def test_config_env_vars():
    """Test that environment variables are correctly parsed when no CLI args are present."""
    env = {
        "IMPERSONATE_PROXY_PORT": "9999",
        "IMPERSONATE_PROXY_HOST": "10.0.0.2",
        "IMPERSONATE_PROXY_IMPERSONATE": "firefox",
        "IMPERSONATE_PROXY_CA_DIR": "/env/ca",
        "IMPERSONATE_PROXY_HEADER_MODE": "override",
        "IMPERSONATE_PROXY_STRIP_CLIENT_LEAK_HEADERS": "true",
        "IMPERSONATE_PROXY_DEBUG": "true",
    }
    with (
        patch("sys.argv", ["impersonate-proxy"]),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once_with(
            host="10.0.0.2",
            port=9999,
            impersonate="firefox",
            ca_dir="/env/ca",
            header_mode="override",
            strip_client_leak_headers=True,
            debug=True,
            quiet=False,
        )


def test_config_cli_args():
    """Test that CLI arguments are correctly parsed when no env vars are present."""
    argv = [
        "impersonate-proxy",
        "--host",
        "192.168.1.50",
        "--port",
        "7777",
        "--impersonate",
        "safari",
        "--ca-dir",
        "/cli/ca",
        "--passthrough-headers",
        "--strip-client-leak-headers",
        "--debug",
    ]
    with (
        patch("sys.argv", argv),
        patch.dict(os.environ, {}, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once_with(
            host="192.168.1.50",
            port=7777,
            impersonate="safari",
            ca_dir="/cli/ca",
            header_mode="passthrough",
            strip_client_leak_headers=True,
            debug=True,
            quiet=False,
        )


def test_config_cli_overrides_env():
    """Test that CLI arguments take precedence over environment variables."""
    env = {
        "IMPERSONATE_PROXY_PORT": "9999",
        "IMPERSONATE_PROXY_HOST": "10.0.0.2",
        "IMPERSONATE_PROXY_IMPERSONATE": "firefox",
        "IMPERSONATE_PROXY_CA_DIR": "/env/ca",
        "IMPERSONATE_PROXY_HEADER_MODE": "enrich",
        "IMPERSONATE_PROXY_STRIP_CLIENT_LEAK_HEADERS": "false",
        "IMPERSONATE_PROXY_DEBUG": "false",
    }
    argv = [
        "impersonate-proxy",
        "--host",
        "192.168.1.50",
        "--port",
        "7777",
        "--impersonate",
        "safari",
        "--ca-dir",
        "/cli/ca",
        "--override-headers",
        "--strip-client-leak-headers",
        "--debug",
    ]
    with (
        patch("sys.argv", argv),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once_with(
            host="192.168.1.50",
            port=7777,
            impersonate="safari",
            ca_dir="/cli/ca",
            header_mode="override",
            strip_client_leak_headers=True,
            debug=True,
            quiet=False,
        )


@pytest.mark.parametrize(
    "env_val,expected_mode",
    [
        ("passthrough", "passthrough"),
        ("enrich", "enrich"),
        ("override", "override"),
        ("", "enrich"),
        ("invalid", "enrich"),
        ("PASSTHROUGH", "passthrough"),
        ("Override", "override"),
    ],
)
def test_config_header_mode_env_variants(env_val, expected_mode):
    """Test IMPERSONATE_PROXY_HEADER_MODE parsing and fallback to enrich."""
    env = {"IMPERSONATE_PROXY_HEADER_MODE": env_val} if env_val else {}
    with (
        patch("sys.argv", ["impersonate-proxy"]),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once()
        assert mock_run.call_args[1]["header_mode"] == expected_mode


@pytest.mark.parametrize(
    "env_val,expected_strip",
    [
        ("true", True),
        ("1", True),
        ("yes", True),
        ("false", False),
        ("0", False),
        ("no", False),
    ],
)
def test_config_strip_leak_env_variants(env_val, expected_strip):
    """Test IMPERSONATE_PROXY_STRIP_CLIENT_LEAK_HEADERS boolean parsing."""
    env = {"IMPERSONATE_PROXY_STRIP_CLIENT_LEAK_HEADERS": env_val}
    with (
        patch("sys.argv", ["impersonate-proxy"]),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once()
        assert mock_run.call_args[1]["strip_client_leak_headers"] is expected_strip


@pytest.mark.parametrize(
    "env_val,expected_debug",
    [
        ("true", True),
        ("1", True),
        ("yes", True),
        ("false", False),
        ("0", False),
        ("no", False),
        ("", False),
    ],
)
def test_config_debug_env_variants(env_val, expected_debug):
    """Test different boolean-like environment variable values for debug mode."""
    env = {"IMPERSONATE_PROXY_DEBUG": env_val}
    with (
        patch("sys.argv", ["impersonate-proxy"]),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once()
        assert mock_run.call_args[1]["debug"] is expected_debug


def test_run_keyboard_interrupt():
    """Test that run() catches KeyboardInterrupt, logs it, and closes the server."""
    from unittest.mock import patch

    with (
        patch("socketserver.BaseServer.serve_forever", side_effect=KeyboardInterrupt),
        patch("socketserver.TCPServer.server_close") as mock_close,
        patch("impersonate_proxy.main._init_ca"),
        patch.dict(os.environ, {}, clear=True),
        patch.object(impersonate_proxy.logger, "info") as mock_info,
    ):
        impersonate_proxy.run(port=0)

    # Verify server_close was called in finally block
    mock_close.assert_called_once()
    # Verify expected log message was recorded
    log_messages = [call.args[0] for call in mock_info.call_args_list]
    log_found = any("Keyboard interrupt received, shutting down..." in msg for msg in log_messages)
    assert log_found, f"Expected KeyboardInterrupt log not found. Logs: {log_messages}"


def test_config_quiet_via_env():
    """Test that quiet mode is enabled when IMPERSONATE_PROXY_QUIET env var is true."""
    env = {"IMPERSONATE_PROXY_QUIET": "true"}
    with (
        patch("sys.argv", ["impersonate-proxy"]),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        expected = dict(_DEFAULT_RUN_CALL)
        expected["quiet"] = True
        mock_run.assert_called_once_with(**expected)


def test_config_quiet_via_cli():
    """Test that quiet mode is enabled when --quiet is passed via CLI."""
    with (
        patch("sys.argv", ["impersonate-proxy", "--quiet"]),
        patch.dict(os.environ, {}, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        expected = dict(_DEFAULT_RUN_CALL)
        expected["quiet"] = True
        mock_run.assert_called_once_with(**expected)


def test_config_quiet_cli_overrides_env():
    """Test that CLI --quiet overrides IMPERSONATE_PROXY_QUIET=false env var."""
    env = {"IMPERSONATE_PROXY_QUIET": "false"}
    with (
        patch("sys.argv", ["impersonate-proxy", "-q"]),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        expected = dict(_DEFAULT_RUN_CALL)
        expected["quiet"] = True
        mock_run.assert_called_once_with(**expected)


@pytest.mark.parametrize(
    "env_val,expected_quiet",
    [
        ("true", True),
        ("1", True),
        ("yes", True),
        ("false", False),
        ("0", False),
        ("no", False),
    ],
)
def test_config_quiet_env_variants(env_val, expected_quiet):
    """Test different boolean-like environment variable values for quiet mode."""
    env = {"IMPERSONATE_PROXY_QUIET": env_val}
    with (
        patch("sys.argv", ["impersonate-proxy"]),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once()
        assert mock_run.call_args[1]["quiet"] is expected_quiet


def test_config_header_modes_mutually_exclusive():
    """Test that passing two header-mode flags triggers argparse error."""
    argv = ["impersonate-proxy", "--passthrough-headers", "--override-headers"]
    with (
        patch("sys.argv", argv),
        patch.dict(os.environ, {}, clear=True),
        patch("argparse.ArgumentParser.error", side_effect=SystemExit(2)) as mock_error,
    ):
        with pytest.raises(SystemExit):
            impersonate_proxy.main()
        mock_error.assert_called_once()

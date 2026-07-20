from __future__ import annotations

import importlib.util
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from unittest import mock


_MODULE_PATH = (
    pathlib.Path(__file__).resolve().parents[1] / "hosts2rpz" / "hosts2rpz.py"
)
_SPEC = importlib.util.spec_from_file_location("hosts2rpz_module", _MODULE_PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
hosts2rpz = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = hosts2rpz
_SPEC.loader.exec_module(hosts2rpz)


class Hosts2RpzTests(unittest.TestCase):
    def test_run_action_passes_feeder_metadata_in_env(self) -> None:
        completed = subprocess.CompletedProcess(args=["/bin/sh", "-c", "echo ok"], returncode=0)

        with mock.patch.object(hosts2rpz.subprocess, "run", return_value=completed) as run_mock:
            with redirect_stdout(io.StringIO()):
                exit_code = hosts2rpz._run_action(
                    'echo "$FEEDER_NAME $FEEDER_EVENT"',
                    "success",
                    "completed",
                    log_timestamp=False,
                    run_id="run-123",
                    log_level="debug",
                    source="https://example.invalid/feed.hosts",
                    output_path="/tmp/adult.zone",
                )

        self.assertEqual(exit_code, 0)
        self.assertEqual(run_mock.call_args.args[0], ["/bin/sh", "-c", 'echo "$FEEDER_NAME $FEEDER_EVENT"'])
        action_env = run_mock.call_args.kwargs["env"]
        self.assertEqual(action_env["FEEDER_NAME"], "hosts2rpz")
        self.assertEqual(action_env["FEEDER_EVENT"], "completed")
        self.assertEqual(action_env["FEEDER_RUN_ID"], "run-123")
        self.assertEqual(action_env["FEEDER_SOURCE"], "https://example.invalid/feed.hosts")
        self.assertEqual(action_env["FEEDER_OUTPUT"], "/tmp/adult.zone")

    def test_collect_http_headers_includes_custom_headers(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "HOSTS2RPZ_HTTP_HEADER_AUTHORIZATION": "Bearer secret-token",
                "HOSTS2RPZ_HTTP_HEADER_X_API_KEY": "abc123",
            },
            clear=True,
        ):
            headers = hosts2rpz._collect_http_headers("hosts2rpz/1.0")

        self.assertEqual(headers["User-Agent"], "hosts2rpz/1.0")
        self.assertEqual(headers["Authorization"], "Bearer secret-token")
        self.assertEqual(headers["X-Api-Key"], "abc123")

    def test_render_zone_uses_full_sinkhole_value(self) -> None:
        zone_text, _ = hosts2rpz._render_zone(
            domains=["example.com"],
            zone_name="rpz.test.",
            ttl=300,
            sinkhole="CNAME rpz-garden.local.",
            add_wildcard=False,
            header_comment=None,
            serial="1",
            soa_refresh=300,
            soa_retry=60,
            soa_expire=604800,
            soa_minimum=300,
        )

        self.assertIn("example.com CNAME rpz-garden.local.", zone_text)
        self.assertNotIn("*.example.com CNAME rpz-garden.local.", zone_text)

    def test_render_zone_does_not_add_wildcard_by_default(self) -> None:
        zone_text, rpz_records = hosts2rpz._render_zone(
            domains=["example.com"],
            zone_name="rpz.test.",
            ttl=300,
            sinkhole="CNAME .",
            add_wildcard=False,
            header_comment=None,
            serial="1",
            soa_refresh=300,
            soa_retry=60,
            soa_expire=604800,
            soa_minimum=300,
        )

        self.assertIn("example.com CNAME .", zone_text)
        self.assertNotIn("*.example.com CNAME .", zone_text)
        self.assertEqual(rpz_records, 1)

    def test_render_zone_adds_wildcard_when_enabled(self) -> None:
        zone_text, rpz_records = hosts2rpz._render_zone(
            domains=["example.com"],
            zone_name="rpz.test.",
            ttl=300,
            sinkhole="CNAME .",
            add_wildcard=True,
            header_comment=None,
            serial="1",
            soa_refresh=300,
            soa_retry=60,
            soa_expire=604800,
            soa_minimum=300,
        )

        self.assertIn("*.example.com CNAME .", zone_text)
        self.assertEqual(rpz_records, 2)

    def test_render_zone_does_not_duplicate_existing_wildcard(self) -> None:
        zone_text, rpz_records = hosts2rpz._render_zone(
            domains=["example.com", "*.example.com"],
            zone_name="rpz.test.",
            ttl=300,
            sinkhole="CNAME .",
            add_wildcard=True,
            header_comment=None,
            serial="1",
            soa_refresh=300,
            soa_retry=60,
            soa_expire=604800,
            soa_minimum=300,
        )

        self.assertEqual(zone_text.count("*.example.com CNAME ."), 1)
        self.assertEqual(rpz_records, 2)

    def test_write_output_atomically_keeps_original_file_on_replace_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "adult.zone")
            with open(output_path, "w", encoding="utf-8") as handle:
                handle.write("original\n")

            with mock.patch.object(
                hosts2rpz.os,
                "replace",
                side_effect=OSError("simulated replace failure"),
            ):
                with self.assertRaises(OSError):
                    hosts2rpz._write_output_atomically(output_path, "updated\n")

            with open(output_path, "r", encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "original\n")

            leftovers = [name for name in os.listdir(directory) if name != "adult.zone"]
            self.assertEqual(leftovers, [])

    def test_read_source_treats_http_304_as_not_modified(self) -> None:
        opener = mock.Mock()
        opener.open.side_effect = urllib.error.HTTPError(
            "https://example.invalid/source.hosts",
            304,
            "Not Modified",
            {},
            None,
        )

        with mock.patch.object(hosts2rpz.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(hosts2rpz._SourceNotModified):
                hosts2rpz._read_source(
                    "https://example.invalid/source.hosts",
                    timeout=30,
                    headers={},
                    max_redirects=3,
                    log_timestamp=False,
                    run_id="run-123",
                    log_level="info",
                )

    def test_main_requires_source_output_and_zone_name(self) -> None:
        cases = [
            ({}, "HOSTS2RPZ_SOURCE"),
            ({"HOSTS2RPZ_SOURCE": "/tmp/source.hosts"}, "HOSTS2RPZ_OUTPUT"),
            (
                {
                    "HOSTS2RPZ_SOURCE": "/tmp/source.hosts",
                    "HOSTS2RPZ_OUTPUT": "/tmp/output.zone",
                },
                "HOSTS2RPZ_ZONE_NAME",
            ),
        ]

        for env_overrides, missing_name in cases:
            stdout = io.StringIO()
            env = {"HOSTS2RPZ_LOG_TIMESTAMP": "false", **env_overrides}
            with self.subTest(missing=missing_name):
                with mock.patch.dict(os.environ, env, clear=True):
                    with mock.patch.object(sys, "argv", ["hosts2rpz.py"]):
                        with redirect_stdout(stdout):
                            exit_code = hosts2rpz.main()

                self.assertEqual(exit_code, 1)
                self.assertIn("event=config_failed", stdout.getvalue())
                self.assertIn(missing_name, stdout.getvalue())

    def test_main_runs_failure_action_without_overriding_original_exit_code(self) -> None:
        stdout = io.StringIO()

        with mock.patch.dict(
            os.environ,
            {
                "HOSTS2RPZ_LOG_TIMESTAMP": "false",
                "HOSTS2RPZ_ACTION_FAILURE": 'echo "$FEEDER_EVENT"',
            },
            clear=True,
        ):
            with mock.patch.object(sys, "argv", ["hosts2rpz.py"]):
                with mock.patch.object(hosts2rpz, "_run_action", return_value=7) as action_mock:
                    with redirect_stdout(stdout):
                        exit_code = hosts2rpz.main()

        self.assertEqual(exit_code, 1)
        self.assertEqual(action_mock.call_args.args[0], 'echo "$FEEDER_EVENT"')
        self.assertEqual(action_mock.call_args.args[1], "failure")
        self.assertEqual(action_mock.call_args.args[2], "config_failed")

    def test_main_returns_error_code_without_raising_on_source_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "adult.zone")
            stdout = io.StringIO()
            env = {
                "HOSTS2RPZ_SOURCE": os.path.join(directory, "missing.hosts"),
                "HOSTS2RPZ_OUTPUT": output_path,
                "HOSTS2RPZ_ZONE_NAME": "rpz.test.",
                "HOSTS2RPZ_LOG_TIMESTAMP": "false",
            }

            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "argv", ["hosts2rpz.py"]):
                    with redirect_stdout(stdout):
                        exit_code = hosts2rpz.main()

        self.assertEqual(exit_code, 1)
        self.assertIn("event=source_failed", stdout.getvalue())
        self.assertNotIn("Traceback", stdout.getvalue())

    def test_main_logs_only_http_header_names(self) -> None:
        hosts_text = "0.0.0.0 example.com\n"
        stdout = io.StringIO()
        env = {
            "HOSTS2RPZ_SOURCE": "https://example.invalid/source.hosts",
            "HOSTS2RPZ_OUTPUT": "/tmp/adult.zone",
            "HOSTS2RPZ_ZONE_NAME": "rpz.test.",
            "HOSTS2RPZ_LOG_LEVEL": "debug",
            "HOSTS2RPZ_LOG_TIMESTAMP": "false",
            "HOSTS2RPZ_USE_ETAG": "false",
            "HOSTS2RPZ_HTTP_HEADER_AUTHORIZATION": "Bearer super-secret-token",
        }

        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch.object(sys, "argv", ["hosts2rpz.py"]):
                with mock.patch.object(hosts2rpz, "_read_source", return_value=(hosts_text, None)):
                    with mock.patch.object(hosts2rpz, "_write_output_atomically"):
                        with redirect_stdout(stdout):
                            exit_code = hosts2rpz.main()

        self.assertEqual(exit_code, 0)
        output = stdout.getvalue()
        self.assertIn("http_header_names=Authorization,User-Agent", output)
        self.assertNotIn("super-secret-token", output)

    def test_main_sends_stored_etag_as_if_none_match(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "adult.zone")
            source = "https://example.invalid/source.hosts"
            hosts2rpz._update_etag_state(
                hosts2rpz._etag_state_path(output_path), source, '"etag-v1"'
            )
            env = {
                "HOSTS2RPZ_SOURCE": source,
                "HOSTS2RPZ_OUTPUT": output_path,
                "HOSTS2RPZ_ZONE_NAME": "rpz.test.",
                "HOSTS2RPZ_LOG_TIMESTAMP": "false",
            }

            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "argv", ["hosts2rpz.py"]):
                    with mock.patch.object(
                        hosts2rpz,
                        "_read_source",
                        return_value=("0.0.0.0 example.com\n", '"etag-v2"'),
                    ) as read_mock:
                        with redirect_stdout(io.StringIO()):
                            exit_code = hosts2rpz.main()

            stored_etag = hosts2rpz._read_etag_state(
                hosts2rpz._etag_state_path(output_path), source
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            read_mock.call_args.kwargs["headers"]["If-None-Match"],
            '"etag-v1"',
        )
        self.assertEqual(stored_etag, '"etag-v2"')

    def test_main_runs_not_modified_action_without_rewriting_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "adult.zone")
            state_path = hosts2rpz._etag_state_path(output_path)
            source = "https://example.invalid/source.hosts"
            with open(output_path, "w", encoding="utf-8") as handle:
                handle.write("existing zone\n")
            hosts2rpz._update_etag_state(state_path, source, '"etag-v1"')
            with open(state_path, "r", encoding="utf-8") as handle:
                original_state = handle.read()
            env = {
                "HOSTS2RPZ_SOURCE": source,
                "HOSTS2RPZ_OUTPUT": output_path,
                "HOSTS2RPZ_ZONE_NAME": "rpz.test.",
                "HOSTS2RPZ_LOG_TIMESTAMP": "false",
                "HOSTS2RPZ_ACTION_NOT_MODIFIED": 'echo "$FEEDER_EVENT"',
            }

            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "argv", ["hosts2rpz.py"]):
                    with mock.patch.object(
                        hosts2rpz,
                        "_read_source",
                        side_effect=hosts2rpz._SourceNotModified(),
                    ):
                        with mock.patch.object(hosts2rpz, "_run_action", return_value=0) as action_mock:
                            with redirect_stdout(io.StringIO()) as stdout:
                                exit_code = hosts2rpz.main()

            with open(output_path, "r", encoding="utf-8") as handle:
                output_text = handle.read()
            with open(state_path, "r", encoding="utf-8") as handle:
                state_text = handle.read()

        self.assertEqual(exit_code, 0)
        self.assertEqual(output_text, "existing zone\n")
        self.assertEqual(state_text, original_state)
        self.assertIn("event=not_modified", stdout.getvalue())
        self.assertEqual(action_mock.call_args.args[1], "not_modified")
        self.assertEqual(action_mock.call_args.args[2], "not_modified")

    def test_main_does_not_write_etag_state_when_success_action_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "adult.zone")
            env = {
                "HOSTS2RPZ_SOURCE": "https://example.invalid/source.hosts",
                "HOSTS2RPZ_OUTPUT": output_path,
                "HOSTS2RPZ_ZONE_NAME": "rpz.test.",
                "HOSTS2RPZ_LOG_TIMESTAMP": "false",
                "HOSTS2RPZ_ACTION_SUCCESS": "exit 9",
            }

            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "argv", ["hosts2rpz.py"]):
                    with mock.patch.object(
                        hosts2rpz,
                        "_read_source",
                        return_value=("0.0.0.0 example.com\n", '"etag-v1"'),
                    ):
                        with mock.patch.object(hosts2rpz, "_run_action", return_value=9):
                            with redirect_stdout(io.StringIO()):
                                exit_code = hosts2rpz.main()

            state_exists = os.path.exists(hosts2rpz._etag_state_path(output_path))

        self.assertEqual(exit_code, 1)
        self.assertFalse(state_exists)

    def test_main_runs_success_action_after_successful_write(self) -> None:
        hosts_text = "0.0.0.0 example.com\n"
        env = {
            "HOSTS2RPZ_SOURCE": "https://example.invalid/source.hosts",
            "HOSTS2RPZ_OUTPUT": "/tmp/adult.zone",
            "HOSTS2RPZ_ZONE_NAME": "rpz.test.",
            "HOSTS2RPZ_LOG_TIMESTAMP": "false",
            "HOSTS2RPZ_USE_ETAG": "false",
            "HOSTS2RPZ_ACTION_SUCCESS": 'echo "$FEEDER_OUTPUT"',
        }

        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch.object(sys, "argv", ["hosts2rpz.py"]):
                with mock.patch.object(hosts2rpz, "_read_source", return_value=(hosts_text, None)):
                    with mock.patch.object(hosts2rpz, "_write_output_atomically"):
                        with mock.patch.object(hosts2rpz, "_run_action", return_value=0) as action_mock:
                            with redirect_stdout(io.StringIO()):
                                exit_code = hosts2rpz.main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(action_mock.call_args.args[0], 'echo "$FEEDER_OUTPUT"')
        self.assertEqual(action_mock.call_args.args[1], "success")
        self.assertEqual(action_mock.call_args.args[2], "completed")

    def test_main_returns_error_when_success_action_fails(self) -> None:
        hosts_text = "0.0.0.0 example.com\n"
        env = {
            "HOSTS2RPZ_SOURCE": "https://example.invalid/source.hosts",
            "HOSTS2RPZ_OUTPUT": "/tmp/adult.zone",
            "HOSTS2RPZ_ZONE_NAME": "rpz.test.",
            "HOSTS2RPZ_LOG_TIMESTAMP": "false",
            "HOSTS2RPZ_USE_ETAG": "false",
            "HOSTS2RPZ_ACTION_SUCCESS": "exit 9",
        }

        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch.object(sys, "argv", ["hosts2rpz.py"]):
                with mock.patch.object(hosts2rpz, "_read_source", return_value=(hosts_text, None)):
                    with mock.patch.object(hosts2rpz, "_write_output_atomically"):
                        with mock.patch.object(hosts2rpz, "_run_action", return_value=9):
                            with redirect_stdout(io.StringIO()):
                                exit_code = hosts2rpz.main()

        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()

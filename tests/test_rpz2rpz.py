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
    pathlib.Path(__file__).resolve().parents[1] / "rpz2rpz" / "rpz2rpz.py"
)
_SPEC = importlib.util.spec_from_file_location("rpz2rpz_module", _MODULE_PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
rpz2rpz = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(rpz2rpz)


class Rpz2RpzTests(unittest.TestCase):
    def test_run_action_passes_feeder_metadata_in_env(self) -> None:
        completed = subprocess.CompletedProcess(args=["/bin/sh", "-c", "echo ok"], returncode=0)

        with mock.patch.object(rpz2rpz.subprocess, "run", return_value=completed) as run_mock:
            with redirect_stdout(io.StringIO()):
                exit_code = rpz2rpz._run_action(
                    'echo "$FEEDER_NAME $FEEDER_EVENT"',
                    "success",
                    "completed",
                    log_timestamp=False,
                    run_id="run-123",
                    log_level="debug",
                    source="https://example.invalid/feed.rpz",
                    output_path="/tmp/phishing.zone",
                )

        self.assertEqual(exit_code, 0)
        self.assertEqual(run_mock.call_args.args[0], ["/bin/sh", "-c", 'echo "$FEEDER_NAME $FEEDER_EVENT"'])
        action_env = run_mock.call_args.kwargs["env"]
        self.assertEqual(action_env["FEEDER_NAME"], "rpz2rpz")
        self.assertEqual(action_env["FEEDER_EVENT"], "completed")
        self.assertEqual(action_env["FEEDER_RUN_ID"], "run-123")
        self.assertEqual(action_env["FEEDER_SOURCE"], "https://example.invalid/feed.rpz")
        self.assertEqual(action_env["FEEDER_OUTPUT"], "/tmp/phishing.zone")

    def test_collect_http_headers_includes_custom_headers(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "RPZ2RPZ_HTTP_HEADER_AUTHORIZATION": "Bearer secret-token",
                "RPZ2RPZ_HTTP_HEADER_X_API_KEY": "abc123",
            },
            clear=True,
        ):
            headers = rpz2rpz._collect_http_headers("rpz2rpz/1.0")

        self.assertEqual(headers["User-Agent"], "rpz2rpz/1.0")
        self.assertEqual(headers["Authorization"], "Bearer secret-token")
        self.assertEqual(headers["X-Api-Key"], "abc123")

    def test_extract_cname_owners_uses_inherited_owner(self) -> None:
        zone_text = (
            "$ORIGIN rpz.source.\n"
            "owner1 CNAME .\n"
            " 600 IN CNAME .\n"
            "owner2 CNAME .\n"
        )

        owners = rpz2rpz._extract_cname_owners(zone_text)

        self.assertEqual(owners, ["owner1", "owner2"])

    def test_extract_cname_owners_deduplicates_case_insensitively(self) -> None:
        zone_text = "Example.COM CNAME .\nexample.com CNAME .\n"

        owners = rpz2rpz._extract_cname_owners(zone_text)

        self.assertEqual(owners, ["Example.COM"])

    def test_parse_zone_entries_recognizes_non_cname_policy_records(self) -> None:
        entries = rpz2rpz._parse_zone_entries(
            "$ORIGIN source.rpz.\n"
            "blocked CNAME .\n"
            "local A 192.0.2.10\n"
            "local6 AAAA 2001:db8::10\n"
            "alias DNAME garden.example.\n"
        )

        self.assertEqual(
            [(entry.owner, entry.rr_type) for entry in entries],
            [
                ("blocked", "CNAME"),
                ("local", "A"),
                ("local6", "AAAA"),
                ("alias", "DNAME"),
            ],
        )

    def test_main_preserves_source_policies_without_sinkhole_setting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_path = os.path.join(directory, "source.rpz")
            output_path = os.path.join(directory, "output.rpz")
            with open(source_path, "w", encoding="utf-8") as handle:
                handle.write(
                    "$TTL 300\n"
                    "$ORIGIN source.rpz.\n"
                    "@ IN SOA ns.source. hostmaster.source. ( 1 300 60 604800 300 )\n"
                    "@ IN NS ns.source.\n"
                    "blocked CNAME garden.example.\n"
                    "local A 192.0.2.10\n"
                    "local6 AAAA 2001:db8::10\n"
                    "alias DNAME target.example.\n"
                )

            env = {
                "RPZ2RPZ_SOURCE": source_path,
                "RPZ2RPZ_OUTPUT": output_path,
                "RPZ2RPZ_ZONE_NAME": "rpz.test.",
                "RPZ2RPZ_LOG_TIMESTAMP": "false",
            }
            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "argv", ["rpz2rpz.py"]):
                    with redirect_stdout(io.StringIO()):
                        exit_code = rpz2rpz.main()

            self.assertEqual(exit_code, 0)
            with open(output_path, "r", encoding="utf-8") as handle:
                output = handle.read()
            self.assertIn("blocked CNAME garden.example.", output)
            self.assertIn("local A 192.0.2.10", output)
            self.assertIn("local6 AAAA 2001:db8::10", output)
            self.assertIn("alias DNAME target.example.", output)
            self.assertNotIn("@ IN SOA ns.source.", output)
            self.assertNotIn("@ IN NS ns.source.", output)

    def test_main_inherits_source_origin_and_ttl_when_env_is_unset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_path = os.path.join(directory, "source.rpz")
            output_path = os.path.join(directory, "output.rpz")
            with open(source_path, "w", encoding="utf-8") as handle:
                handle.write(
                    "; RPZ file from Blockhub\n"
                    "$TTL 600\n"
                    "$ORIGIN source.rpz.\n"
                    "blocked CNAME garden.example.\n"
                )

            env = {
                "RPZ2RPZ_SOURCE": source_path,
                "RPZ2RPZ_OUTPUT": output_path,
                "RPZ2RPZ_LOG_TIMESTAMP": "false",
            }
            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "argv", ["rpz2rpz.py"]):
                    with redirect_stdout(io.StringIO()):
                        exit_code = rpz2rpz.main()

            self.assertEqual(exit_code, 0)
            with open(output_path, "r", encoding="utf-8") as handle:
                output = handle.read()
            self.assertEqual(output.splitlines()[0], "; RPZ file from Blockhub")
            self.assertEqual(output.count("; RPZ file from Blockhub"), 1)
            self.assertIn("$TTL 600", output)
            self.assertIn("$ORIGIN source.rpz.", output)
            self.assertEqual(output.count("$TTL 600"), 1)
            self.assertEqual(output.count("$ORIGIN source.rpz."), 1)
            self.assertIn("blocked CNAME garden.example.", output)

    def test_main_rewrites_every_source_origin_and_ttl_when_env_is_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_path = os.path.join(directory, "source.rpz")
            output_path = os.path.join(directory, "output.rpz")
            with open(source_path, "w", encoding="utf-8") as handle:
                handle.write(
                    "$TTL 600\n"
                    "$ORIGIN source.rpz.\n"
                    "$TTL 900\n"
                    "$ORIGIN later.rpz.\n"
                    "blocked CNAME garden.example.\n"
                )

            env = {
                "RPZ2RPZ_SOURCE": source_path,
                "RPZ2RPZ_OUTPUT": output_path,
                "RPZ2RPZ_ZONE_NAME": "local.rpz.",
                "RPZ2RPZ_TTL": "300",
                "RPZ2RPZ_LOG_TIMESTAMP": "false",
            }
            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "argv", ["rpz2rpz.py"]):
                    with redirect_stdout(io.StringIO()):
                        exit_code = rpz2rpz.main()

            self.assertEqual(exit_code, 0)
            with open(output_path, "r", encoding="utf-8") as handle:
                output = handle.read()
            self.assertNotIn("$TTL 600", output)
            self.assertNotIn("$TTL 900", output)
            self.assertNotIn("$ORIGIN source.rpz.", output)
            self.assertNotIn("$ORIGIN later.rpz.", output)
            self.assertEqual(output.count("$TTL 300"), 1)
            self.assertEqual(output.count("$ORIGIN local.rpz."), 1)

    def test_main_fails_without_effective_origin_or_ttl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_path = os.path.join(directory, "source.rpz")
            output_path = os.path.join(directory, "output.rpz")
            with open(source_path, "w", encoding="utf-8") as handle:
                handle.write("blocked CNAME .\n")

            env = {
                "RPZ2RPZ_SOURCE": source_path,
                "RPZ2RPZ_OUTPUT": output_path,
                "RPZ2RPZ_LOG_TIMESTAMP": "false",
            }
            stdout = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "argv", ["rpz2rpz.py"]):
                    with redirect_stdout(stdout):
                        exit_code = rpz2rpz.main()

            self.assertEqual(exit_code, 1)
            self.assertIn("event=config_failed", stdout.getvalue())
            self.assertIn("RPZ2RPZ_ZONE_NAME", stdout.getvalue())

    def test_main_rewrites_all_source_policies_when_sinkhole_is_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_path = os.path.join(directory, "source.rpz")
            output_path = os.path.join(directory, "output.rpz")
            with open(source_path, "w", encoding="utf-8") as handle:
                handle.write(
                    "blocked CNAME garden.example.\n"
                    "local A 192.0.2.10\n"
                    "local6 AAAA 2001:db8::10\n"
                )

            env = {
                "RPZ2RPZ_SOURCE": source_path,
                "RPZ2RPZ_OUTPUT": output_path,
                "RPZ2RPZ_ZONE_NAME": "rpz.test.",
                "RPZ2RPZ_TTL": "300",
                "RPZ2RPZ_SINKHOLE": "CNAME .",
                "RPZ2RPZ_LOG_TIMESTAMP": "false",
            }
            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "argv", ["rpz2rpz.py"]):
                    with redirect_stdout(io.StringIO()):
                        exit_code = rpz2rpz.main()

            self.assertEqual(exit_code, 0)
            with open(output_path, "r", encoding="utf-8") as handle:
                output = handle.read()
            self.assertIn("blocked CNAME .", output)
            self.assertIn("local CNAME .", output)
            self.assertIn("local6 CNAME .", output)
            self.assertNotIn("garden.example.", output)
            self.assertNotIn("192.0.2.10", output)
            self.assertNotIn("2001:db8::10", output)

    def test_main_accepts_source_with_only_non_cname_policies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_path = os.path.join(directory, "source.rpz")
            output_path = os.path.join(directory, "output.rpz")
            with open(source_path, "w", encoding="utf-8") as handle:
                handle.write("local A 192.0.2.10\nlocal6 AAAA 2001:db8::10\n")

            env = {
                "RPZ2RPZ_SOURCE": source_path,
                "RPZ2RPZ_OUTPUT": output_path,
                "RPZ2RPZ_ZONE_NAME": "rpz.test.",
                "RPZ2RPZ_TTL": "300",
                "RPZ2RPZ_LOG_TIMESTAMP": "false",
            }
            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "argv", ["rpz2rpz.py"]):
                    with redirect_stdout(io.StringIO()):
                        exit_code = rpz2rpz.main()

            self.assertEqual(exit_code, 0)
            with open(output_path, "r", encoding="utf-8") as handle:
                output = handle.read()
            self.assertIn("local A 192.0.2.10", output)
            self.assertIn("local6 AAAA 2001:db8::10", output)

    def test_sinkhole_from_env_rejects_an_empty_value(self) -> None:
        with mock.patch.dict(
            os.environ, {"RPZ2RPZ_SINKHOLE": "  "}, clear=True
        ):
            with self.assertRaisesRegex(ValueError, "must not be empty"):
                rpz2rpz._sinkhole_from_env()

    def test_render_zone_uses_full_sinkhole_value(self) -> None:
        zone_text, _ = rpz2rpz._render_zone(
            owners=["example.com"],
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

    def test_render_zone_does_not_add_wildcard_by_default(self) -> None:
        zone_text, rpz_records = rpz2rpz._render_zone(
            owners=["example.com"],
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
        zone_text, rpz_records = rpz2rpz._render_zone(
            owners=["example.com"],
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

        self.assertIn("example.com CNAME .", zone_text)
        self.assertIn("*.example.com CNAME .", zone_text)
        self.assertEqual(rpz_records, 2)

    def test_render_zone_does_not_duplicate_existing_wildcard(self) -> None:
        zone_text, rpz_records = rpz2rpz._render_zone(
            owners=["example.com", "*.example.com"],
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
            output_path = os.path.join(directory, "phishing.zone")
            with open(output_path, "w", encoding="utf-8") as handle:
                handle.write("original\n")

            with mock.patch.object(
                rpz2rpz.os,
                "replace",
                side_effect=OSError("simulated replace failure"),
            ):
                with self.assertRaises(OSError):
                    rpz2rpz._write_output_atomically(output_path, "updated\n")

            with open(output_path, "r", encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "original\n")

            leftovers = [name for name in os.listdir(directory) if name != "phishing.zone"]
            self.assertEqual(leftovers, [])

    def test_read_source_treats_http_304_as_not_modified(self) -> None:
        opener = mock.Mock()
        opener.open.side_effect = urllib.error.HTTPError(
            "https://example.invalid/source.rpz",
            304,
            "Not Modified",
            {},
            None,
        )

        with mock.patch.object(rpz2rpz.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(rpz2rpz._SourceNotModified):
                rpz2rpz._read_source(
                    "https://example.invalid/source.rpz",
                    timeout=30,
                    headers={},
                    max_redirects=3,
                    log_timestamp=False,
                    run_id="run-123",
                    log_level="info",
                )

    def test_main_returns_error_code_without_raising_on_source_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "phishing.zone")
            stdout = io.StringIO()
            env = {
                "RPZ2RPZ_SOURCE": os.path.join(directory, "missing.zone"),
                "RPZ2RPZ_OUTPUT": output_path,
                "RPZ2RPZ_ZONE_NAME": "rpz.test.",
                "RPZ2RPZ_LOG_TIMESTAMP": "false",
            }

            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "argv", ["rpz2rpz.py"]):
                    with redirect_stdout(stdout):
                        exit_code = rpz2rpz.main()

        self.assertEqual(exit_code, 1)
        self.assertIn("event=source_failed", stdout.getvalue())
        self.assertNotIn("Traceback", stdout.getvalue())

    def test_main_requires_source_and_output(self) -> None:
        stdout = io.StringIO()

        with mock.patch.dict(
            os.environ,
            {
                "RPZ2RPZ_LOG_TIMESTAMP": "false",
            },
            clear=True,
        ):
            with mock.patch.object(sys, "argv", ["rpz2rpz.py"]):
                with redirect_stdout(stdout):
                    exit_code = rpz2rpz.main()

        self.assertEqual(exit_code, 1)
        self.assertIn("event=config_failed", stdout.getvalue())
        self.assertIn("RPZ2RPZ_SOURCE", stdout.getvalue())

    def test_main_runs_failure_action_without_overriding_original_exit_code(self) -> None:
        stdout = io.StringIO()

        with mock.patch.dict(
            os.environ,
            {
                "RPZ2RPZ_LOG_TIMESTAMP": "false",
                "RPZ2RPZ_ACTION_FAILURE": 'echo "$FEEDER_EVENT"',
            },
            clear=True,
        ):
            with mock.patch.object(sys, "argv", ["rpz2rpz.py"]):
                with mock.patch.object(rpz2rpz, "_run_action", return_value=7) as action_mock:
                    with redirect_stdout(stdout):
                        exit_code = rpz2rpz.main()

        self.assertEqual(exit_code, 1)
        self.assertEqual(action_mock.call_args.args[0], 'echo "$FEEDER_EVENT"')
        self.assertEqual(action_mock.call_args.args[1], "failure")
        self.assertEqual(action_mock.call_args.args[2], "config_failed")

    def test_main_logs_only_http_header_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_path = os.path.join(directory, "source.zone")
            with open(source_path, "w", encoding="utf-8") as handle:
                handle.write("example.com CNAME .\n")
            with open(source_path, "r", encoding="utf-8") as handle:
                source_text = handle.read()

            stdout = io.StringIO()
            env = {
                "RPZ2RPZ_SOURCE": "https://example.invalid/source.rpz",
                "RPZ2RPZ_OUTPUT": os.path.join(directory, "phishing.zone"),
                "RPZ2RPZ_ZONE_NAME": "rpz.test.",
                "RPZ2RPZ_TTL": "300",
                "RPZ2RPZ_LOG_LEVEL": "debug",
                "RPZ2RPZ_LOG_TIMESTAMP": "false",
                "RPZ2RPZ_HTTP_HEADER_AUTHORIZATION": "Bearer super-secret-token",
            }

            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "argv", ["rpz2rpz.py"]):
                    with mock.patch.object(
                        rpz2rpz,
                        "_read_source",
                        return_value=(source_text, '"etag-v1"'),
                    ):
                        with redirect_stdout(stdout):
                            exit_code = rpz2rpz.main()

        self.assertEqual(exit_code, 0)
        output = stdout.getvalue()
        self.assertIn("http_header_names=Authorization,User-Agent", output)
        self.assertNotIn("super-secret-token", output)

    def test_main_sends_stored_etag_as_if_none_match(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "phishing.zone")
            source = "https://example.invalid/source.rpz"
            rpz2rpz._update_etag_state(
                rpz2rpz._etag_state_path(output_path),
                source,
                '"etag-v1"',
            )
            env = {
                "RPZ2RPZ_SOURCE": source,
                "RPZ2RPZ_OUTPUT": output_path,
                "RPZ2RPZ_ZONE_NAME": "rpz.test.",
                "RPZ2RPZ_TTL": "300",
                "RPZ2RPZ_LOG_TIMESTAMP": "false",
            }

            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "argv", ["rpz2rpz.py"]):
                    with mock.patch.object(
                        rpz2rpz,
                        "_read_source",
                        return_value=("example.com CNAME .\n", '"etag-v2"'),
                    ) as read_mock:
                        with redirect_stdout(io.StringIO()):
                            exit_code = rpz2rpz.main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            read_mock.call_args.kwargs["headers"]["If-None-Match"],
            '"etag-v1"',
        )

    def test_main_does_not_override_manual_if_none_match_header(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "phishing.zone")
            source = "https://example.invalid/source.rpz"
            rpz2rpz._update_etag_state(
                rpz2rpz._etag_state_path(output_path),
                source,
                '"etag-v1"',
            )
            env = {
                "RPZ2RPZ_SOURCE": source,
                "RPZ2RPZ_OUTPUT": output_path,
                "RPZ2RPZ_ZONE_NAME": "rpz.test.",
                "RPZ2RPZ_TTL": "300",
                "RPZ2RPZ_LOG_TIMESTAMP": "false",
                "RPZ2RPZ_HTTP_HEADER_IF_NONE_MATCH": '"manual-etag"',
            }

            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "argv", ["rpz2rpz.py"]):
                    with mock.patch.object(
                        rpz2rpz,
                        "_read_source",
                        return_value=("example.com CNAME .\n", '"etag-v2"'),
                    ) as read_mock:
                        with redirect_stdout(io.StringIO()):
                            exit_code = rpz2rpz.main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            read_mock.call_args.kwargs["headers"]["If-None-Match"],
            '"manual-etag"',
        )

    def test_main_does_not_use_or_update_etag_when_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "phishing.zone")
            state_path = rpz2rpz._etag_state_path(output_path)
            source = "https://example.invalid/source.rpz"
            rpz2rpz._update_etag_state(state_path, source, '"etag-v1"')
            with open(state_path, "r", encoding="utf-8") as handle:
                original_state = handle.read()
            env = {
                "RPZ2RPZ_SOURCE": source,
                "RPZ2RPZ_OUTPUT": output_path,
                "RPZ2RPZ_ZONE_NAME": "rpz.test.",
                "RPZ2RPZ_TTL": "300",
                "RPZ2RPZ_LOG_TIMESTAMP": "false",
                "RPZ2RPZ_USE_ETAG": "false",
            }

            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "argv", ["rpz2rpz.py"]):
                    with mock.patch.object(
                        rpz2rpz,
                        "_read_source",
                        return_value=("example.com CNAME .\n", '"etag-v2"'),
                    ) as read_mock:
                        with redirect_stdout(io.StringIO()):
                            exit_code = rpz2rpz.main()

            with open(state_path, "r", encoding="utf-8") as handle:
                state_text = handle.read()

        self.assertEqual(exit_code, 0)
        self.assertNotIn("If-None-Match", read_mock.call_args.kwargs["headers"])
        self.assertEqual(state_text, original_state)

    def test_main_runs_not_modified_action_without_rewriting_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "phishing.zone")
            state_path = rpz2rpz._etag_state_path(output_path)
            source = "https://example.invalid/source.rpz"
            with open(output_path, "w", encoding="utf-8") as handle:
                handle.write("existing zone\n")
            rpz2rpz._update_etag_state(state_path, source, '"etag-v1"')
            with open(state_path, "r", encoding="utf-8") as handle:
                original_state = handle.read()
            env = {
                "RPZ2RPZ_SOURCE": source,
                "RPZ2RPZ_OUTPUT": output_path,
                "RPZ2RPZ_ZONE_NAME": "rpz.test.",
                "RPZ2RPZ_TTL": "300",
                "RPZ2RPZ_LOG_TIMESTAMP": "false",
                "RPZ2RPZ_ACTION_NOT_MODIFIED": 'echo "$FEEDER_EVENT"',
            }

            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "argv", ["rpz2rpz.py"]):
                    with mock.patch.object(
                        rpz2rpz,
                        "_read_source",
                        side_effect=rpz2rpz._SourceNotModified(),
                    ):
                        with mock.patch.object(rpz2rpz, "_run_action", return_value=0) as action_mock:
                            with redirect_stdout(io.StringIO()) as stdout:
                                exit_code = rpz2rpz.main()

            with open(output_path, "r", encoding="utf-8") as handle:
                output_text = handle.read()
            with open(state_path, "r", encoding="utf-8") as handle:
                state_text = handle.read()

        self.assertEqual(exit_code, 0)
        self.assertEqual(output_text, "existing zone\n")
        self.assertEqual(state_text, original_state)
        self.assertIn("event=not_modified", stdout.getvalue())
        self.assertEqual(action_mock.call_args.args[0], 'echo "$FEEDER_EVENT"')
        self.assertEqual(action_mock.call_args.args[1], "not_modified")
        self.assertEqual(action_mock.call_args.args[2], "not_modified")

    def test_main_writes_etag_state_after_success_action(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "phishing.zone")
            source = "https://example.invalid/source.rpz"
            env = {
                "RPZ2RPZ_SOURCE": source,
                "RPZ2RPZ_OUTPUT": output_path,
                "RPZ2RPZ_ZONE_NAME": "rpz.test.",
                "RPZ2RPZ_TTL": "300",
                "RPZ2RPZ_LOG_TIMESTAMP": "false",
                "RPZ2RPZ_ACTION_SUCCESS": 'echo "$FEEDER_EVENT"',
            }

            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "argv", ["rpz2rpz.py"]):
                    with mock.patch.object(
                        rpz2rpz,
                        "_read_source",
                        return_value=("example.com CNAME .\n", '"etag-v1"'),
                    ):
                        with mock.patch.object(rpz2rpz, "_run_action", return_value=0):
                            with redirect_stdout(io.StringIO()):
                                exit_code = rpz2rpz.main()

            stored_etag = rpz2rpz._read_etag_state(
                rpz2rpz._etag_state_path(output_path), source
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(stored_etag, '"etag-v1"')

    def test_main_does_not_write_etag_state_when_success_action_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "phishing.zone")
            env = {
                "RPZ2RPZ_SOURCE": "https://example.invalid/source.rpz",
                "RPZ2RPZ_OUTPUT": output_path,
                "RPZ2RPZ_ZONE_NAME": "rpz.test.",
                "RPZ2RPZ_TTL": "300",
                "RPZ2RPZ_LOG_TIMESTAMP": "false",
                "RPZ2RPZ_ACTION_SUCCESS": "exit 9",
            }

            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "argv", ["rpz2rpz.py"]):
                    with mock.patch.object(
                        rpz2rpz,
                        "_read_source",
                        return_value=("example.com CNAME .\n", '"etag-v1"'),
                    ):
                        with mock.patch.object(rpz2rpz, "_run_action", return_value=9):
                            with redirect_stdout(io.StringIO()):
                                exit_code = rpz2rpz.main()

            state_exists = os.path.exists(rpz2rpz._etag_state_path(output_path))

        self.assertEqual(exit_code, 1)
        self.assertFalse(state_exists)

    def test_main_runs_success_action_after_successful_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_path = os.path.join(directory, "source.zone")
            with open(source_path, "w", encoding="utf-8") as handle:
                handle.write("example.com CNAME .\n")
            with open(source_path, "r", encoding="utf-8") as handle:
                source_text = handle.read()

            env = {
                "RPZ2RPZ_SOURCE": source_path,
                "RPZ2RPZ_OUTPUT": os.path.join(directory, "phishing.zone"),
                "RPZ2RPZ_ZONE_NAME": "rpz.test.",
                "RPZ2RPZ_TTL": "300",
                "RPZ2RPZ_LOG_TIMESTAMP": "false",
                "RPZ2RPZ_ACTION_SUCCESS": 'echo "$FEEDER_OUTPUT"',
            }

            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "argv", ["rpz2rpz.py"]):
                    with mock.patch.object(
                        rpz2rpz,
                        "_read_source",
                        return_value=(source_text, None),
                    ):
                        with mock.patch.object(rpz2rpz, "_run_action", return_value=0) as action_mock:
                            with redirect_stdout(io.StringIO()):
                                exit_code = rpz2rpz.main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(action_mock.call_args.args[0], 'echo "$FEEDER_OUTPUT"')
        self.assertEqual(action_mock.call_args.args[1], "success")
        self.assertEqual(action_mock.call_args.args[2], "completed")

    def test_main_returns_error_when_success_action_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_path = os.path.join(directory, "source.zone")
            with open(source_path, "w", encoding="utf-8") as handle:
                handle.write("example.com CNAME .\n")
            with open(source_path, "r", encoding="utf-8") as handle:
                source_text = handle.read()

            env = {
                "RPZ2RPZ_SOURCE": source_path,
                "RPZ2RPZ_OUTPUT": os.path.join(directory, "phishing.zone"),
                "RPZ2RPZ_ZONE_NAME": "rpz.test.",
                "RPZ2RPZ_TTL": "300",
                "RPZ2RPZ_LOG_TIMESTAMP": "false",
                "RPZ2RPZ_ACTION_SUCCESS": 'exit 9',
            }

            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(sys, "argv", ["rpz2rpz.py"]):
                    with mock.patch.object(
                        rpz2rpz,
                        "_read_source",
                        return_value=(source_text, None),
                    ):
                        with mock.patch.object(rpz2rpz, "_run_action", return_value=9):
                            with redirect_stdout(io.StringIO()):
                                exit_code = rpz2rpz.main()

        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()

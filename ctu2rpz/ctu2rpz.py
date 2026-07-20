#!/usr/bin/env python3
"""ctu2rpz: download a CSV blocklist and render an RPZ zone file."""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable


_LOG_LEVELS = {"debug": 10, "info": 20, "error": 40}
_HTTP_HEADER_PREFIX = "CTU2RPZ_HTTP_HEADER_"
_FEEDER_NAME = "ctu2rpz"


class _SourceNotModified(Exception):
    """The HTTP source responded with 304 Not Modified."""


def _utc_timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _new_run_id() -> str:
    prefix = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _elapsed_ms(start: float) -> str:
    return str(round((time.perf_counter() - start) * 1000))


def _format_serial_time(serial: str) -> str:
    return datetime.fromtimestamp(int(serial), timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def _normalize_log_level(value: str | None) -> str:
    if value is None:
        return "info"
    level = value.strip().lower()
    if level in _LOG_LEVELS:
        return level
    return "info"


def _normalize_sinkhole(value: str | None) -> str:
    if value is None:
        return "CNAME ."

    sinkhole = value.strip()
    if sinkhole == "":
        return "CNAME ."
    return sinkhole


def _normalize_zone_name(value: str | None) -> str:
    zone_name = (value or "rpz.example.").strip()
    if not zone_name.endswith("."):
        zone_name += "."
    return zone_name


def _normalize_header_comment(value: str | None) -> str | None:
    if value is None:
        return None
    comment = value.strip()
    if not comment:
        return None
    return comment.lstrip("#;").strip()


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _required_env(name: str) -> str:
    value = _env(name)
    if value is None:
        raise ValueError(f"Missing required environment variable: {name}")
    return value


def _format_log_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    if text == "" or any(char.isspace() for char in text):
        escaped = (
            text.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
        )
        return f'"{escaped}"'
    return text


def _log(
    event: str,
    include_timestamp: bool,
    run_id: str,
    level: str = "info",
    min_level: str = "info",
    include_run: bool = True,
    **fields: object,
) -> None:
    if _LOG_LEVELS[level] < _LOG_LEVELS[min_level]:
        return

    parts = []
    if include_timestamp:
        parts.append(f"ts={_utc_timestamp()}")
    parts.append(f"level={level}")
    if include_run:
        parts.append(f"run={run_id}")
    parts.append(f"event={event}")
    for key, value in fields.items():
        parts.append(f"{key}={_format_log_value(value)}")
    print(" ".join(parts))


def _load_dotenv(path: str) -> None:
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            if "=" not in raw:
                continue
            key, value = raw.split("=", 1)
            key = key.strip()
            value = value.strip().strip("\"").strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


class _LimitedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, max_redirects: int) -> None:
        super().__init__()
        self._max_redirects = max_redirects
        self._redirects = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self._redirects += 1
        if self._redirects > self._max_redirects:
            raise urllib.error.HTTPError(
                req.full_url,
                code,
                f"Too many redirects (limit {self._max_redirects})",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _header_name_from_env(name: str) -> str:
    return "-".join(part.capitalize() for part in name.split("_") if part)


def _collect_http_headers(user_agent: str | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    if user_agent:
        headers["User-Agent"] = user_agent

    for env_name, raw_value in sorted(os.environ.items()):
        if not env_name.startswith(_HTTP_HEADER_PREFIX):
            continue

        header_suffix = env_name[len(_HTTP_HEADER_PREFIX) :]
        header_name = _header_name_from_env(header_suffix)
        if not header_name:
            continue

        header_value = raw_value.strip()
        if not header_value:
            continue

        headers[header_name] = header_value

    return headers


def _is_http_source(source: str) -> bool:
    return source.startswith("http://") or source.startswith("https://")


def _has_http_header(headers: dict[str, str], name: str) -> bool:
    return any(header_name.lower() == name.lower() for header_name in headers)


def _etag_state_path(output_path: str) -> str:
    return f"{output_path}.etag"


def _read_etag_state(state_path: str, source: str) -> str | None:
    try:
        with open(state_path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None

    if not isinstance(state, dict) or state.get("source") != source:
        return None

    etag = state.get("etag")
    if not isinstance(etag, str) or not etag.strip():
        return None
    return etag


@dataclass(frozen=True)
class CsvStats:
    total_records: int
    active_records: int
    removed_records: int
    empty_url_records: int
    invalid_url_records: int
    normalized_records: int
    normalized_changed_records: int
    duplicate_records: int
    unique_domains: int


def _normalize_domain(value: str) -> str | None:
    raw = value.strip()
    if not raw:
        return None

    if "://" in raw:
        host = urllib.parse.urlsplit(raw).hostname
    else:
        host = raw
        for separator in ("/", "?", "#"):
            host = host.split(separator, 1)[0]
        if "@" in host:
            host = host.rsplit("@", 1)[-1]
        if host.startswith("[") and "]" in host:
            host = host[1 : host.index("]")]
        elif ":" in host:
            host = host.split(":", 1)[0]

    if host is None:
        return None

    host = host.strip().strip(".").lower()
    wildcard_prefix = "*." if host.startswith("*.") else ""
    domain = host[2:] if wildcard_prefix else host

    if (
        not domain
        or any(char.isspace() for char in domain)
        or any(char in domain for char in "/\\:")
    ):
        return None

    labels = domain.split(".")
    if any(label == "" for label in labels):
        return None

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    return f"{wildcard_prefix}{domain}"


def _read_source(
    source: str,
    timeout: int,
    headers: dict[str, str],
    max_redirects: int,
    log_timestamp: bool,
    run_id: str,
    log_level: str,
) -> tuple[str, str | None]:
    if _is_http_source(source):
        request = urllib.request.Request(source, headers=headers)
        opener = urllib.request.build_opener(
            _LimitedRedirectHandler(max_redirects=max_redirects)
        )
        try:
            with opener.open(request, timeout=timeout) as response:
                final_url = response.geturl()
                if final_url != source:
                    _log(
                        "redirect_source",
                        log_timestamp,
                        run_id,
                        level="debug",
                        min_level=log_level,
                        url=source,
                    )
                    _log(
                        "redirect_final",
                        log_timestamp,
                        run_id,
                        level="debug",
                        min_level=log_level,
                        url=final_url,
                    )
                return response.read().decode("utf-8"), response.headers.get("ETag")
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                exc.close()
                raise _SourceNotModified from None
            raise
    with open(source, "r", encoding="utf-8") as handle:
        return handle.read(), None


def _iter_active_domains(csv_text: str) -> tuple[list[str], CsvStats]:
    reader = csv.DictReader(io.StringIO(csv_text))
    required = {"URL", "DATUM_VYMAZU"}
    missing = required - set(reader.fieldnames or [])
    if missing:
        raise ValueError(f"CSV missing required columns: {', '.join(sorted(missing))}")

    total_records = 0
    removed_records = 0
    empty_url_records = 0
    invalid_url_records = 0
    normalized_changed_records = 0
    domains: list[str] = []

    for row in reader:
        total_records += 1
        url = (row.get("URL") or "").strip()
        removal = (row.get("DATUM_VYMAZU") or "").strip()
        if not url:
            empty_url_records += 1
            continue
        if removal:
            removed_records += 1
            continue
        domain = _normalize_domain(url)
        if domain is None:
            invalid_url_records += 1
            continue
        if domain != url.strip().strip(".").lower():
            normalized_changed_records += 1
        domains.append(domain)

    unique_domains = len(set(domains))
    stats = CsvStats(
        total_records=total_records,
        active_records=total_records - removed_records - empty_url_records,
        removed_records=removed_records,
        empty_url_records=empty_url_records,
        invalid_url_records=invalid_url_records,
        normalized_records=len(domains),
        normalized_changed_records=normalized_changed_records,
        duplicate_records=len(domains) - unique_domains,
        unique_domains=unique_domains,
    )
    return domains, stats


def _render_zone(
    domains: Iterable[str],
    zone_name: str,
    ttl: int,
    sinkhole: str,
    add_wildcard: bool,
    header_comment: str | None,
    serial: str,
    soa_refresh: int,
    soa_retry: int,
    soa_expire: int,
    soa_minimum: int,
) -> tuple[str, int]:
    lines: list[str] = []
    if header_comment:
        lines.append(f"; {header_comment}")
    lines.append(f"$TTL {ttl}")
    lines.append(f"$ORIGIN {zone_name}")
    lines.append(f"@ IN SOA {zone_name} hostmaster.{zone_name} (")
    lines.append(f"           {serial} ; serial {_format_serial_time(serial)}")
    lines.append(f"           {soa_refresh} ; refresh")
    lines.append(f"           {soa_retry} ; retry")
    lines.append(f"           {soa_expire} ; expire")
    lines.append(f"           {soa_minimum} ; minimum")
    lines.append("           )")
    lines.append("@ IN NS localhost.")

    source_domains = list(domains)
    rpz_records = 0
    known_domains = set(source_domains)
    emitted = set()
    for domain in source_domains:
        if domain in emitted:
            continue
        emitted.add(domain)
        lines.append(f"{domain} {sinkhole}")
        rpz_records += 1
        wildcard_domain = f"*.{domain}"
        if (
            add_wildcard
            and not domain.startswith("*.")
            and wildcard_domain not in known_domains
            and wildcard_domain not in emitted
        ):
            lines.append(f"*.{domain} {sinkhole}")
            emitted.add(wildcard_domain)
            rpz_records += 1

    return "\n".join(lines) + "\n", rpz_records


def _write_text_atomically(path: str, content: str) -> None:
    output_dir = os.path.dirname(os.path.abspath(path))
    os.makedirs(output_dir, exist_ok=True)

    file_descriptor, temporary_path = tempfile.mkstemp(
        dir=output_dir,
        prefix=f".{os.path.basename(path)}.",
        suffix=".tmp",
        text=True,
    )
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except Exception:
        try:
            os.unlink(temporary_path)
        except OSError:
            pass
        raise


def _write_output_atomically(output_path: str, zone_text: str) -> None:
    _write_text_atomically(output_path, zone_text)


def _update_etag_state(state_path: str, source: str, etag: str | None) -> None:
    if etag and etag.strip():
        state_text = json.dumps({"source": source, "etag": etag.strip()}, sort_keys=True)
        _write_text_atomically(state_path, f"{state_text}\n")
        return

    try:
        os.unlink(state_path)
    except FileNotFoundError:
        pass


def _build_action_env(
    feeder_event: str,
    run_id: str,
    source: str | None,
    output_path: str | None,
) -> dict[str, str]:
    action_env = os.environ.copy()
    action_env.update(
        {
            "FEEDER_NAME": _FEEDER_NAME,
            "FEEDER_EVENT": feeder_event,
            "FEEDER_RUN_ID": run_id,
            "FEEDER_SOURCE": source or "",
            "FEEDER_OUTPUT": output_path or "",
        }
    )
    return action_env


def _run_action(
    command: str,
    action_name: str,
    feeder_event: str,
    log_timestamp: bool,
    run_id: str,
    log_level: str,
    source: str | None,
    output_path: str | None,
) -> int:
    action_started_at = time.perf_counter()
    _log(
        "action_started",
        log_timestamp,
        run_id,
        level="debug",
        min_level=log_level,
        action=action_name,
        trigger_event=feeder_event,
    )

    try:
        completed = subprocess.run(
            ["/bin/sh", "-c", command],
            check=False,
            env=_build_action_env(feeder_event, run_id, source, output_path),
        )
    except Exception as exc:
        _log(
            "action_failed",
            log_timestamp,
            run_id,
            level="error",
            min_level=log_level,
            duration_ms=_elapsed_ms(action_started_at),
            action=action_name,
            trigger_event=feeder_event,
            error_type=type(exc).__name__,
            message=str(exc),
        )
        return 1

    if completed.returncode != 0:
        _log(
            "action_failed",
            log_timestamp,
            run_id,
            level="error",
            min_level=log_level,
            duration_ms=_elapsed_ms(action_started_at),
            action=action_name,
            trigger_event=feeder_event,
            exit_code=completed.returncode,
        )
        return completed.returncode

    _log(
        "action_completed",
        log_timestamp,
        run_id,
        level="debug",
        min_level=log_level,
        duration_ms=_elapsed_ms(action_started_at),
        action=action_name,
        trigger_event=feeder_event,
    )
    return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ctu2rpz")
    parser.add_argument(
        "--config",
        help="Path to env file to load before reading environment variables.",
    )
    return parser.parse_args()


def main() -> int:
    started_at = time.perf_counter()
    args = _parse_args()
    if args.config:
        _load_dotenv(args.config)
    # Without --config we only use process environment variables.

    run_id = _new_run_id()
    log_timestamp = _bool_env("CTU2RPZ_LOG_TIMESTAMP", True)
    log_level = _normalize_log_level(_env("CTU2RPZ_LOG_LEVEL", "info"))
    action_success = _env("CTU2RPZ_ACTION_SUCCESS")
    action_not_modified = _env("CTU2RPZ_ACTION_NOT_MODIFIED")
    action_failure = _env("CTU2RPZ_ACTION_FAILURE")
    source = ""
    output_path = ""

    def fail(event: str, **fields: object) -> int:
        _log(
            event,
            log_timestamp,
            run_id,
            level="error",
            min_level=log_level,
            **fields,
        )
        if action_failure:
            _run_action(
                action_failure,
                "failure",
                event,
                log_timestamp,
                run_id,
                log_level,
                source,
                output_path,
            )
        return 1

    try:
        source = _required_env("CTU2RPZ_SOURCE")
        output_path = _required_env("CTU2RPZ_OUTPUT")
        zone_name = _normalize_zone_name(_required_env("CTU2RPZ_ZONE_NAME"))
        ttl = int(_env("CTU2RPZ_TTL", "300"))
        soa_refresh = int(_env("CTU2RPZ_SOA_REFRESH", "300"))
        soa_retry = int(_env("CTU2RPZ_SOA_RETRY", "60"))
        soa_expire = int(_env("CTU2RPZ_SOA_EXPIRE", "604800"))
        soa_minimum = int(_env("CTU2RPZ_SOA_MINIMUM", "300"))
        sinkhole = _normalize_sinkhole(_env("CTU2RPZ_SINKHOLE", "CNAME ."))
        add_wildcard = _bool_env("CTU2RPZ_ADD_WILDCARD", False)
        header_comment = _normalize_header_comment(_env("CTU2RPZ_HEADER_COMMENT"))
        use_etag = _bool_env("CTU2RPZ_USE_ETAG", True)
        timeout = int(_env("CTU2RPZ_TIMEOUT", "30"))
        max_redirects = int(_env("CTU2RPZ_MAX_REDIRECTS", "3"))
        user_agent = _env("CTU2RPZ_USER_AGENT", "ctu2rpz/1.0")
        http_headers = _collect_http_headers(user_agent)
    except Exception as exc:
        return fail(
            "config_failed",
            error_type=type(exc).__name__,
            message=str(exc),
        )

    etag_state_path = _etag_state_path(output_path)
    if use_etag and _is_http_source(source):
        stored_etag = _read_etag_state(etag_state_path, source)
        if stored_etag and not _has_http_header(http_headers, "If-None-Match"):
            http_headers["If-None-Match"] = stored_etag

    _log("started", log_timestamp, run_id, level="debug", min_level=log_level)
    _log(
        "zone_config",
        log_timestamp,
        run_id,
        level="debug",
        min_level=log_level,
        output=output_path,
        zone_name=zone_name,
        ttl=ttl,
        add_wildcard=add_wildcard,
        soa_refresh=soa_refresh,
        soa_retry=soa_retry,
        soa_expire=soa_expire,
        soa_minimum=soa_minimum,
        sinkhole=sinkhole,
        header_comment=header_comment,
        use_etag=use_etag,
    )

    source_fields: dict[str, object] = {"source": source}
    if _is_http_source(source):
        source_fields["timeout"] = timeout
        source_fields["max_redirects"] = max_redirects
        source_fields["use_etag"] = use_etag
        source_fields["if_none_match"] = _has_http_header(http_headers, "If-None-Match")
        if http_headers:
            source_fields["http_header_names"] = ",".join(sorted(http_headers))
    _log(
        "source",
        log_timestamp,
        run_id,
        level="debug",
        min_level=log_level,
        **source_fields,
    )

    step_started_at = time.perf_counter()
    try:
        csv_text, response_etag = _read_source(
            source,
            timeout=timeout,
            headers=http_headers,
            max_redirects=max_redirects,
            log_timestamp=log_timestamp,
            run_id=run_id,
            log_level=log_level,
        )
    except _SourceNotModified:
        _log(
            "not_modified",
            log_timestamp,
            run_id,
            min_level=log_level,
            include_run=log_level == "debug",
            duration_ms=_elapsed_ms(step_started_at),
        )
        if action_not_modified:
            action_exit_code = _run_action(
                action_not_modified,
                "not_modified",
                "not_modified",
                log_timestamp,
                run_id,
                log_level,
                source,
                output_path,
            )
            if action_exit_code != 0:
                return 1
        return 0
    except Exception as exc:
        return fail(
            "source_failed",
            duration_ms=_elapsed_ms(step_started_at),
            error_type=type(exc).__name__,
            message=str(exc),
        )
    _log(
        "source_read",
        log_timestamp,
        run_id,
        level="debug",
        min_level=log_level,
        duration_ms=_elapsed_ms(step_started_at),
        bytes=len(csv_text.encode("utf-8")),
    )

    step_started_at = time.perf_counter()
    try:
        raw_domains, stats = _iter_active_domains(csv_text)
    except Exception as exc:
        return fail(
            "csv_failed",
            duration_ms=_elapsed_ms(step_started_at),
            error_type=type(exc).__name__,
            message=str(exc),
        )
    domains = sorted(set(raw_domains))
    _log(
        "csv_processed",
        log_timestamp,
        run_id,
        level="debug",
        min_level=log_level,
        duration_ms=_elapsed_ms(step_started_at),
        total_records=stats.total_records,
        active_records=stats.active_records,
        removed_records=stats.removed_records,
        empty_url_records=stats.empty_url_records,
        invalid_url_records=stats.invalid_url_records,
        normalized_records=stats.normalized_records,
        normalized_changed_records=stats.normalized_changed_records,
        duplicate_records=stats.duplicate_records,
        unique_domains=stats.unique_domains,
    )

    serial = str(int(time.time()))
    step_started_at = time.perf_counter()
    try:
        zone_text, rpz_records = _render_zone(
            domains=domains,
            zone_name=zone_name,
            ttl=ttl,
            sinkhole=sinkhole,
            add_wildcard=add_wildcard,
            header_comment=header_comment,
            serial=serial,
            soa_refresh=soa_refresh,
            soa_retry=soa_retry,
            soa_expire=soa_expire,
            soa_minimum=soa_minimum,
        )
    except Exception as exc:
        return fail(
            "zone_render_failed",
            duration_ms=_elapsed_ms(step_started_at),
            error_type=type(exc).__name__,
            message=str(exc),
        )
    _log(
        "zone_rendered",
        log_timestamp,
        run_id,
        level="debug",
        min_level=log_level,
        duration_ms=_elapsed_ms(step_started_at),
        serial=serial,
        domains=len(domains),
        rpz_records=rpz_records,
    )

    step_started_at = time.perf_counter()
    try:
        _write_output_atomically(output_path, zone_text)
    except Exception as exc:
        return fail(
            "rpz_write_failed",
            duration_ms=_elapsed_ms(step_started_at),
            destination=output_path,
            error_type=type(exc).__name__,
            message=str(exc),
        )
    _log(
        "rpz_written",
        log_timestamp,
        run_id,
        level="debug",
        min_level=log_level,
        duration_ms=_elapsed_ms(step_started_at),
        destination=output_path,
        domains=len(domains),
        rpz_records=rpz_records,
        bytes=len(zone_text.encode("utf-8")),
    )
    if action_success:
        action_exit_code = _run_action(
            action_success,
            "success",
            "completed",
            log_timestamp,
            run_id,
            log_level,
            source,
            output_path,
        )
        if action_exit_code != 0:
            return 1
    if use_etag and _is_http_source(source):
        step_started_at = time.perf_counter()
        try:
            _update_etag_state(etag_state_path, source, response_etag)
        except Exception as exc:
            return fail(
                "etag_state_failed",
                duration_ms=_elapsed_ms(step_started_at),
                destination=etag_state_path,
                error_type=type(exc).__name__,
                message=str(exc),
            )
        _log(
            "etag_state_updated",
            log_timestamp,
            run_id,
            level="debug",
            min_level=log_level,
            destination=etag_state_path,
            present=bool(response_etag and response_etag.strip()),
        )
    _log(
        "completed",
        log_timestamp,
        run_id,
        min_level=log_level,
        include_run=log_level == "debug",
        duration_ms=_elapsed_ms(started_at),
        domains=len(domains),
        rpz_records=rpz_records,
    )

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)

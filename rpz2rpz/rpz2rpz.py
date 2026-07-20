#!/usr/bin/env python3
"""rpz2rpz: normalize an RPZ zone file."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone


_LOG_LEVELS = {"debug": 10, "info": 20, "error": 40}
_DNS_CLASSES = {"IN", "CH", "HS"}
_TTL_RE = re.compile(r"\d[\dWDHMSwdhms]*\Z")
_HTTP_HEADER_PREFIX = "RPZ2RPZ_HTTP_HEADER_"
_FEEDER_NAME = "rpz2rpz"


class _SourceNotModified(Exception):
    """The HTTP source responded with 304 Not Modified."""


class _ZoneEntry:
    def __init__(
        self,
        owner: str,
        rr_type: str,
        start_line: int,
        end_line: int,
    ) -> None:
        self.owner = owner
        self.rr_type = rr_type
        self.start_line = start_line
        self.end_line = end_line


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


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _normalize_log_level(value: str | None) -> str:
    if value is None:
        return "info"
    level = value.strip().lower()
    if level in _LOG_LEVELS:
        return level
    return "info"


def _sinkhole_from_env() -> str | None:
    value = os.getenv("RPZ2RPZ_SINKHOLE")
    if value is None:
        return None

    sinkhole = value.strip()
    if not sinkhole:
        raise ValueError("RPZ2RPZ_SINKHOLE must not be empty")
    return sinkhole


def _source_directive_value(zone_text: str, directive: str) -> str | None:
    for line in zone_text.splitlines():
        without_comment = line.split(";", 1)[0].strip()
        if not without_comment:
            continue
        tokens = without_comment.split(None, 1)
        if len(tokens) == 2 and tokens[0].upper() == directive.upper():
            value = tokens[1].strip()
            if value:
                return value
    return None


def _effective_zone_setting(
    env_name: str, source_value: str | None
) -> tuple[str, bool]:
    raw_value = os.getenv(env_name)
    if raw_value is not None:
        value = raw_value.strip()
        if not value:
            raise ValueError(f"{env_name} must not be empty")
        return value, True
    if source_value is None:
        raise ValueError(f"Missing {env_name} and corresponding source directive")
    return source_value, False


def _rewrite_source_directives(
    source_lines: list[str], directive: str, value: str | None
) -> list[str]:
    if value is None:
        return source_lines

    rewritten: list[str] = []
    for line in source_lines:
        without_comment, separator, comment = line.partition(";")
        tokens = without_comment.strip().split(None, 1)
        if tokens and tokens[0].upper() == directive.upper():
            prefix = without_comment[: len(without_comment) - len(without_comment.lstrip())]
            line = f"{prefix}{directive} {value}"
            if separator:
                line += f";{comment}"
        rewritten.append(line)
    return rewritten


def _header_directive_line_indices(
    source_lines: list[str], directive: str, remove_all: bool
) -> set[int]:
    line_indices: set[int] = set()
    removed = False
    for line_index, line in enumerate(source_lines):
        without_comment = line.split(";", 1)[0].strip()
        tokens = without_comment.split(None, 1)
        is_directive = tokens and tokens[0].upper() == directive.upper()
        if is_directive and (remove_all or not removed):
            removed = True
            line_indices.add(line_index)
            continue
    return line_indices


def _leading_source_comments(source_lines: list[str]) -> tuple[list[str], set[int]]:
    comments: list[str] = []
    line_indices: set[int] = set()
    for line_index, line in enumerate(source_lines):
        stripped = line.strip()
        if not stripped:
            line_indices.add(line_index)
            continue
        if stripped.startswith(";"):
            comments.append(line)
            line_indices.add(line_index)
            continue
        break
    return comments, line_indices


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


def _is_dns_class(token: str) -> bool:
    return token.upper() in _DNS_CLASSES


def _is_ttl(token: str) -> bool:
    return _TTL_RE.fullmatch(token) is not None


def _infer_owner(
    tokens_before_type: list[str],
    line_starts_with_whitespace: bool,
    current_owner: str | None,
) -> str | None:
    if not tokens_before_type:
        return None

    if line_starts_with_whitespace and all(
        _is_ttl(token) or _is_dns_class(token) for token in tokens_before_type
    ):
        return current_owner

    return tokens_before_type[0]


def _normalize_owner_key(owner: str) -> str:
    return owner.rstrip(".").lower()


def _required_env(name: str) -> str:
    value = _env(name)
    if value is None:
        raise ValueError(f"Missing required environment variable: {name}")
    return value


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


def _extract_cname_owners(zone_text: str) -> list[str]:
    owners: list[str] = []
    seen = set()
    current_owner: str | None = None

    for line in zone_text.splitlines():
        without_comment = line.split(";", 1)[0].rstrip()
        stripped = without_comment.strip()
        if not stripped or stripped.startswith(";") or stripped.startswith("$"):
            continue

        tokens = stripped.split()
        cname_index = next(
            (
                index
                for index, token in enumerate(tokens)
                if token.upper() == "CNAME"
            ),
            None,
        )
        if cname_index is None or cname_index == 0 or cname_index + 1 >= len(tokens):
            continue

        owner = _infer_owner(
            tokens[:cname_index],
            line_starts_with_whitespace=without_comment[:1].isspace(),
            current_owner=current_owner,
        )
        if owner is None:
            continue

        current_owner = owner
        owner_key = _normalize_owner_key(owner)
        if owner_key in seen:
            continue
        seen.add(owner_key)
        owners.append(owner)

    return owners


def _parse_zone_entries(zone_text: str) -> list[_ZoneEntry]:
    entries: list[_ZoneEntry] = []
    current_owner: str | None = None
    lines = zone_text.splitlines()
    line_index = 0

    while line_index < len(lines):
        start_line = line_index
        raw_lines = [lines[line_index]]
        without_comment = lines[line_index].split(";", 1)[0].rstrip()
        paren_depth = without_comment.count("(") - without_comment.count(")")
        line_index += 1
        while paren_depth > 0 and line_index < len(lines):
            raw_line = lines[line_index]
            raw_lines.append(raw_line)
            without_comment = raw_line.split(";", 1)[0].rstrip()
            paren_depth += without_comment.count("(") - without_comment.count(")")
            line_index += 1

        first_line = raw_lines[0]
        without_comment = first_line.split(";", 1)[0].rstrip()
        stripped = without_comment.strip()
        if not stripped or stripped.startswith(";") or stripped.startswith("$"):
            continue

        tokens = stripped.split()
        if first_line[:1].isspace():
            owner = _infer_owner(tokens, True, current_owner)
            record_tokens = tokens
        else:
            owner = tokens[0] if tokens else None
            record_tokens = tokens[1:]

        if owner is None:
            continue

        while record_tokens and (
            _is_ttl(record_tokens[0]) or _is_dns_class(record_tokens[0])
        ):
            record_tokens = record_tokens[1:]
        if not record_tokens:
            continue

        rr_type = record_tokens[0].upper()
        current_owner = owner
        entries.append(
            _ZoneEntry(
                owner=owner,
                rr_type=rr_type,
                start_line=start_line,
                end_line=line_index,
            )
        )

    return entries


def _validate_zone(zone_text: str) -> list[_ZoneEntry]:
    if not zone_text.strip():
        raise ValueError("Downloaded zone is empty")

    entries = _parse_zone_entries(zone_text)
    if not any(entry.rr_type not in {"SOA", "NS"} for entry in entries):
        raise ValueError("Downloaded zone contains no policy records")

    return entries


def _render_zone(
    owners: list[str] | list[_ZoneEntry],
    zone_name: str,
    ttl: str | int,
    sinkhole: str | None,
    add_wildcard: bool,
    header_comment: str | None,
    serial: str,
    soa_refresh: int,
    soa_retry: int,
    soa_expire: int,
    soa_minimum: int,
    source_lines: list[str] | None = None,
    skipped_source_lines: set[int] | None = None,
) -> tuple[str, int]:
    lines: list[str] = []
    source_comments: list[str] = []
    source_comment_lines: set[int] = set()
    if source_lines is not None:
        source_comments, source_comment_lines = _leading_source_comments(source_lines)
    lines.extend(source_comments)
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

    zone_entries = [entry for entry in owners if isinstance(entry, _ZoneEntry)]
    policy_entries = [
        entry for entry in zone_entries if entry.rr_type not in {"SOA", "NS"}
    ]

    if sinkhole is None:
        if source_lines is None:
            raise ValueError("Source lines are required when preserving policies")
        skipped_lines = {
            line_index
            for entry in zone_entries
            if entry.rr_type in {"SOA", "NS"}
            for line_index in range(entry.start_line, entry.end_line)
        }
        skipped_lines.update(skipped_source_lines or set())
        skipped_lines.update(source_comment_lines)
        lines.extend(
            line for line_index, line in enumerate(source_lines) if line_index not in skipped_lines
        )
        return "\n".join(lines) + "\n", len(policy_entries)

    owners = (
        [entry.owner for entry in policy_entries]
        if zone_entries
        else [owner for owner in owners if isinstance(owner, str)]
    )
    rpz_records = 0
    source_owners = {_normalize_owner_key(owner) for owner in owners}
    emitted = set()
    for owner in owners:
        owner_key = _normalize_owner_key(owner)
        if owner_key in emitted:
            continue
        emitted.add(owner_key)
        lines.append(f"{owner} {sinkhole}")
        rpz_records += 1
        wildcard_owner = f"*.{owner}"
        wildcard_key = _normalize_owner_key(wildcard_owner)
        if (
            add_wildcard
            and not owner.startswith("*.")
            and wildcard_key not in source_owners
            and wildcard_key not in emitted
        ):
            lines.append(f"{wildcard_owner} {sinkhole}")
            emitted.add(wildcard_key)
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
    parser = argparse.ArgumentParser(description="rpz2rpz")
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

    run_id = _new_run_id()
    log_timestamp = _bool_env("RPZ2RPZ_LOG_TIMESTAMP", True)
    log_level = _normalize_log_level(_env("RPZ2RPZ_LOG_LEVEL", "info"))
    action_success = _env("RPZ2RPZ_ACTION_SUCCESS")
    action_not_modified = _env("RPZ2RPZ_ACTION_NOT_MODIFIED")
    action_failure = _env("RPZ2RPZ_ACTION_FAILURE")
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
        source = _required_env("RPZ2RPZ_SOURCE")
        output_path = _required_env("RPZ2RPZ_OUTPUT")
        soa_refresh = int(_env("RPZ2RPZ_SOA_REFRESH", "300"))
        soa_retry = int(_env("RPZ2RPZ_SOA_RETRY", "60"))
        soa_expire = int(_env("RPZ2RPZ_SOA_EXPIRE", "604800"))
        soa_minimum = int(_env("RPZ2RPZ_SOA_MINIMUM", "300"))
        header_comment = _normalize_header_comment(_env("RPZ2RPZ_HEADER_COMMENT"))
        sinkhole = _sinkhole_from_env()
        add_wildcard = _bool_env("RPZ2RPZ_ADD_WILDCARD", False)
        use_etag = _bool_env("RPZ2RPZ_USE_ETAG", True)
        timeout = int(_env("RPZ2RPZ_TIMEOUT", "30"))
        max_redirects = int(_env("RPZ2RPZ_MAX_REDIRECTS", "3"))
        user_agent = _env("RPZ2RPZ_USER_AGENT", "rpz2rpz/1.0")
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

    source_fields: dict[str, object] = {"source": source}
    if source.startswith("http://") or source.startswith("https://"):
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
        zone_text, response_etag = _read_source(
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

    source_bytes = len(zone_text.encode("utf-8"))
    _log(
        "source_read",
        log_timestamp,
        run_id,
        level="debug",
        min_level=log_level,
        duration_ms=_elapsed_ms(step_started_at),
        bytes=source_bytes,
    )

    try:
        source_origin = _source_directive_value(zone_text, "$ORIGIN")
        source_ttl = _source_directive_value(zone_text, "$TTL")
        zone_name_value, zone_name_overridden = _effective_zone_setting(
            "RPZ2RPZ_ZONE_NAME", source_origin
        )
        ttl, ttl_overridden = _effective_zone_setting("RPZ2RPZ_TTL", source_ttl)
        if not _is_ttl(ttl):
            raise ValueError("RPZ2RPZ_TTL must be a valid DNS TTL")
        zone_name = _normalize_zone_name(zone_name_value)
        source_lines = _rewrite_source_directives(
            zone_text.splitlines(), "$ORIGIN", zone_name if zone_name_overridden else None
        )
        source_lines = _rewrite_source_directives(
            source_lines, "$TTL", ttl if ttl_overridden else None
        )
        header_directive_lines = _header_directive_line_indices(
            source_lines, "$ORIGIN", zone_name_overridden
        )
        header_directive_lines.update(
            _header_directive_line_indices(source_lines, "$TTL", ttl_overridden)
        )
    except Exception as exc:
        return fail(
            "config_failed",
            error_type=type(exc).__name__,
            message=str(exc),
        )

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
        header_comment=header_comment,
        sinkhole=sinkhole,
        use_etag=use_etag,
    )

    step_started_at = time.perf_counter()
    try:
        zone_entries = _validate_zone(zone_text)
    except Exception as exc:
        return fail(
            "zone_validation_failed",
            duration_ms=_elapsed_ms(step_started_at),
            error_type=type(exc).__name__,
            message=str(exc),
        )
    _log(
        "zone_validated",
        log_timestamp,
        run_id,
        level="debug",
        min_level=log_level,
        duration_ms=_elapsed_ms(step_started_at),
        rpz_records=sum(
            entry.rr_type not in {"SOA", "NS"} for entry in zone_entries
        ),
    )

    serial = str(int(time.time()))
    step_started_at = time.perf_counter()
    try:
        zone_text, rpz_records = _render_zone(
            owners=zone_entries,
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
            source_lines=source_lines,
            skipped_source_lines=header_directive_lines,
        )
    except Exception as exc:
        return fail(
            "zone_render_failed",
            duration_ms=_elapsed_ms(step_started_at),
            error_type=type(exc).__name__,
            message=str(exc),
        )
    output_bytes = len(zone_text.encode("utf-8"))
    _log(
        "zone_rendered",
        log_timestamp,
        run_id,
        level="debug",
        min_level=log_level,
        duration_ms=_elapsed_ms(step_started_at),
        serial=serial,
        sinkhole=sinkhole,
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
        rpz_records=rpz_records,
        bytes=output_bytes,
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
        rpz_records=rpz_records,
        bytes=output_bytes,
    )

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)

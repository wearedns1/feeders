# hosts2rpz

`hosts2rpz` converts a classic hosts blocklist to an RPZ zone.

## Input

Set `HOSTS2RPZ_SOURCE` to an HTTP(S) URL or local hosts file. Blank lines and
comments are ignored. Each usable line starts with an IP address; every
following value on that line is treated as a domain. Domains are normalized to
lowercase IDNA ASCII.

## Run

Copy `.env.example` to `.env`, set the required values, and run:

```sh
python3 hosts2rpz.py --config ./.env
```

Required values:

- `HOSTS2RPZ_SOURCE` — source URL or file
- `HOSTS2RPZ_OUTPUT` — destination RPZ file
- `HOSTS2RPZ_ZONE_NAME` — RPZ zone name, normally ending with `.`

## Main settings

| Setting | Default | Purpose |
| --- | --- | --- |
| `HOSTS2RPZ_SINKHOLE` | `CNAME .` | Policy written after each domain |
| `HOSTS2RPZ_ADD_WILDCARD` | `false` | Add wildcard records for exact domains |
| `HOSTS2RPZ_TTL` | `300` | Record TTL |
| `HOSTS2RPZ_USE_ETAG` | `true` | Use ETag caching for HTTP sources |
| `HOSTS2RPZ_TIMEOUT` | `30` | HTTP timeout in seconds |
| `HOSTS2RPZ_LOG_LEVEL` | `info` | `info` or `debug` logging |

The generated zone includes a local SOA and NS header. Its serial is the
current Unix time. Output is written atomically.

## HTTP and actions

For HTTP inputs, custom request headers use
`HOSTS2RPZ_HTTP_HEADER_<NAME>`. For example, the suffix
`AUTHORIZATION` becomes the header `Authorization`; set its value to
`Bearer <token>`. Header values are never written to the logs.

Put optional actions in `.env`. If actions are enabled, configure all three
outcomes together: `HOSTS2RPZ_ACTION_SUCCESS`,
`HOSTS2RPZ_ACTION_NOT_MODIFIED`, and `HOSTS2RPZ_ACTION_FAILURE`. Do not add
only one action as a one-off environment-variable prefix to the command. See
the root [README](../README.md#actions) for action behavior and available
metadata.

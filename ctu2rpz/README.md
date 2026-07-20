# ctu2rpz

`ctu2rpz` converts a CSV blocklist to an RPZ zone.

## Input

Set `CTU2RPZ_SOURCE` to an HTTP(S) URL or local CSV file. The CSV must contain
the `URL` and `DATUM_VYMAZU` columns. Only rows with an empty `DATUM_VYMAZU`
value are used. URLs are converted to DNS hostnames.

## Run

Copy `.env.example` to `.env`, set the required values, and run:

```sh
python3 ctu2rpz.py --config ./.env
```

Required values:

- `CTU2RPZ_SOURCE` — source URL or file
- `CTU2RPZ_OUTPUT` — destination RPZ file
- `CTU2RPZ_ZONE_NAME` — RPZ zone name, normally ending with `.`

## Main settings

| Setting | Default | Purpose |
| --- | --- | --- |
| `CTU2RPZ_SINKHOLE` | `CNAME .` | Policy written after each domain |
| `CTU2RPZ_ADD_WILDCARD` | `false` | Add wildcard records for exact domains |
| `CTU2RPZ_TTL` | `300` | Record TTL |
| `CTU2RPZ_USE_ETAG` | `true` | Use ETag caching for HTTP sources |
| `CTU2RPZ_TIMEOUT` | `30` | HTTP timeout in seconds |
| `CTU2RPZ_LOG_LEVEL` | `info` | `info` or `debug` logging |

The generated zone includes a local SOA and NS header. Its serial is the
current Unix time. Output is written atomically.

## HTTP and actions

For HTTP inputs, custom request headers use
`CTU2RPZ_HTTP_HEADER_<NAME>`. For example, the suffix
`AUTHORIZATION` becomes the header `Authorization`; set its value to
`Bearer <token>`. Header values are never written to the logs.

Put optional actions in `.env`. If actions are enabled, configure all three
outcomes together: `CTU2RPZ_ACTION_SUCCESS`,
`CTU2RPZ_ACTION_NOT_MODIFIED`, and `CTU2RPZ_ACTION_FAILURE`. Do not add only
one action as a one-off environment-variable prefix to the command. See the
root [README](../README.md#actions) for action behavior and available metadata.

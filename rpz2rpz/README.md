# rpz2rpz

`rpz2rpz` reads an existing RPZ zone and writes a new, locally owned RPZ zone.

## Input

Set `RPZ2RPZ_SOURCE` to an HTTP(S) URL or local RPZ file. By default, the tool
keeps every source policy record, including CNAME, A, AAAA, DNAME, and wildcard
records. It replaces the source SOA and NS records with a locally generated
header.

## Run

Copy `.env.example` to `.env`, set the required values, and run:

```sh
python3 rpz2rpz.py --config ./.env
```

Required values:

- `RPZ2RPZ_SOURCE` — source URL or file
- `RPZ2RPZ_OUTPUT` — destination RPZ file

## Main settings

| Setting | Default | Purpose |
| --- | --- | --- |
| `RPZ2RPZ_SINKHOLE` | unset | Preserve source policies; set a value to rewrite every policy owner |
| `RPZ2RPZ_ADD_WILDCARD` | `false` | Add wildcard records for exact owners |
| `RPZ2RPZ_ZONE_NAME` | source `$ORIGIN` | Zone name for the local SOA and NS header |
| `RPZ2RPZ_TTL` | source `$TTL` | Record TTL for the local header |
| `RPZ2RPZ_USE_ETAG` | `true` | Use ETag caching for HTTP sources |
| `RPZ2RPZ_TIMEOUT` | `30` | HTTP timeout in seconds |
| `RPZ2RPZ_LOG_LEVEL` | `info` | `info` or `debug` logging |

The generated zone includes a local SOA and NS header. Its serial is the
current Unix time. Output is written atomically.

## Policy mode

Leave `RPZ2RPZ_SINKHOLE` unset to preserve source policies. Set it to a full
RPZ policy value, such as `CNAME .`, to rewrite every source policy owner to
that value. An empty value is invalid.

## Zone settings

Leave `RPZ2RPZ_ZONE_NAME` and `RPZ2RPZ_TTL` unset to use the source `$ORIGIN`
and `$TTL` directives. Set either value to use it in the local header and to
replace every matching directive from the source. The feeder fails if it has no
effective origin or TTL.

## HTTP and actions

For HTTP inputs, custom request headers use
`RPZ2RPZ_HTTP_HEADER_<NAME>`. For example, the suffix
`AUTHORIZATION` becomes the header `Authorization`; set its value to
`Bearer <token>`. Header values are never written to the logs.

Put optional actions in `.env`. If actions are enabled, configure all three
outcomes together: `RPZ2RPZ_ACTION_SUCCESS`,
`RPZ2RPZ_ACTION_NOT_MODIFIED`, and `RPZ2RPZ_ACTION_FAILURE`. Do not add only
one action as a one-off environment-variable prefix to the command. See the
root [README](../README.md#actions) for action behavior and available metadata.

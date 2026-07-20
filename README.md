# Feeders

Small, dependency-free Python tools that turn public blocklists into DNS
Response Policy Zone (RPZ) files.

| Tool | Reads | Produces |
| --- | --- | --- |
| [ctu2rpz](./ctu2rpz/) | CSV blocklist | RPZ zone |
| [hosts2rpz](./hosts2rpz/) | hosts file | RPZ zone |
| [rpz2rpz](./rpz2rpz/) | RPZ zone | RPZ zone |

## Requirements

- Python 3.10 or newer
- No third-party packages

## Quick start

Each tool has an `.env.example` file. Copy it to a private configuration file,
set the source, output path, and zone name, then run the tool.

```sh
cd hosts2rpz
cp .env.example .env
# Edit .env
python3 hosts2rpz.py --config ./.env
```

`ctu2rpz` and `hosts2rpz` require their `*_SOURCE`, `*_OUTPUT`, and
`*_ZONE_NAME` variables. `rpz2rpz` requires only source and output; it can
inherit its zone name and TTL from the source RPZ. A source can be an HTTP(S)
URL or a local file.

## What every tool does

- builds a complete RPZ zone with a local SOA and NS header;
- writes the new file atomically, so a failed write does not leave a partial
  zone file;
- uses `CNAME .` as the default RPZ policy, except that `rpz2rpz` preserves
  source policies until `RPZ2RPZ_SINKHOLE` is set;
- can add `*.` records when `*_ADD_WILDCARD=true`;
- logs concise `key=value` lines suitable for automation.

## HTTP sources

ETag handling is enabled by default. After a successful run, the tool stores
the ETag in `<output>.etag` and uses it on the next request. A `304 Not
Modified` response leaves the zone and ETag file unchanged.

Set `*_USE_ETAG=false` to disable this behavior. Custom request headers use
the `*_HTTP_HEADER_<NAME>` form; underscores in `<NAME>` become hyphens.
For example, `*_HTTP_HEADER_AUTHORIZATION=Bearer example-token` sends an
`Authorization` header with a bearer token.

## Actions

Optional shell commands can run after a successful update, an unchanged HTTP
source, or a failed run. Configure actions in the `.env` file, not as a
one-off prefix to the run command. When actions are used, define the complete
set for all three outcomes:

- `*_ACTION_SUCCESS`
- `*_ACTION_NOT_MODIFIED`
- `*_ACTION_FAILURE`

The commands run through `/bin/sh -c`. They receive `FEEDER_NAME`,
`FEEDER_EVENT`, `FEEDER_RUN_ID`, `FEEDER_SOURCE`, and `FEEDER_OUTPUT` as
environment variables. A failing success action makes the run fail; a failure
action never hides the original error.

See the README in each tool directory for its input format and settings.

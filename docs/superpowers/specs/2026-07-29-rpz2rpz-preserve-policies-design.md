# rpz2rpz: preserve source policies by default

## Goal

When `RPZ2RPZ_SINKHOLE` is not set, `rpz2rpz` must retain all resource
records that express policies in the source RPZ zone. This includes CNAME, A,
AAAA, DNAME, wildcard, and other source policy records. The generated output
keeps its own SOA and NS header.

## Configuration

| Setting | Unset behavior | Set behavior |
| --- | --- | --- |
| `RPZ2RPZ_SINKHOLE` | Preserve source policy records. | Rewrite every source policy owner to the non-empty value. |
| `RPZ2RPZ_ZONE_NAME` | Use the source `$ORIGIN`. | Use the non-empty value and replace every source `$ORIGIN`. |
| `RPZ2RPZ_TTL` | Use the source `$TTL`. | Use the positive value and replace every source `$TTL`. |

`CNAME .` remains the explicit opt-in value for rewriting every policy to
NXDOMAIN. A missing effective origin or TTL, or an explicitly empty override,
is a configuration error.

## Preserve mode

The feeder resolves the effective origin and TTL before it writes the generated
SOA and NS header. It uses explicit configuration when present; otherwise it
uses the corresponding source directive. It then carries source directives and
every source resource record forward without changing their text or policy
target. Source SOA and NS records are excluded so the output has exactly one
locally generated zone header.

The source directive used for the local header is omitted from the copied
source body, so each effective origin and TTL appears only once. When an origin
or TTL override is configured, every source directive of that kind is omitted;
the generated header is the sole directive and prevents later source content
from overriding the requested setting. Later source directives without an
explicit override remain in place to preserve their semantics.

## Rewrite mode

The feeder finds every source resource-record owner except source SOA and NS
records. It emits each distinct owner once with the configured sinkhole value.
`RPZ2RPZ_ADD_WILDCARD=true` continues to add a wildcard for an exact owner only
when the source has no explicit wildcard owner.

## Validation and tests

Tests will cover preservation of CNAME, A, AAAA, DNAME, wildcard records, and
source directives; exclusion of source SOA and NS records; rewrite behavior
with an explicit sinkhole; and rejection of an empty sinkhole setting.

The README and `.env.example` will state that unset sinkhole, origin, and TTL
settings inherit source behavior. The `.env.example` file will enable only
`RPZ2RPZ_SOURCE` and `RPZ2RPZ_OUTPUT`; all other settings, including zone name,
remain commented examples.

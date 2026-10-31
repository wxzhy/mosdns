# Cache correctness and background refresh

The cache keys on the DNS question (including QCLASS), AD/CD/DO flags, and
canonical query name. Queries containing answer-affecting EDNS options,
including ECS, bypass the shared cache. A downstream operation that introduces
such an option also prevents the frontend, lazy refresh, and prefetch workers
from writing its result under an ordinary key.

When prefetch is enabled, each newly populated cache entry remembers the
continuation that produced it. Prefetch never uses a global first-caller
continuation. Entries loaded from a dump have no executable continuation and
cannot be proactively prefetched until a fresh response stores one.

**Policy boundary:** The default `scope: shared` keeps a common cache across
compatible sequences, including ordinary A and HTTPS auxiliary A lookups in
the SmartDNS examples. To isolate different sequence continuations using the
same cache plugin, explicitly set:

```yaml
args:
  scope: sequence
```

Sequence-scoped keys include the sequence identity and the continuation
position. Named sequences have restart-stable identities in cache dumps;
anonymous programmatic sequences use process-local identities and their dump
entries should not be expected to match after restart. Queries taking different
policy paths *within the same continuation* can still share responses; use
separate cache plugins or route before cache when stricter isolation is
required. Switching from shared to sequence scope makes existing shared dump
entries unreachable until refreshed.

An ECS handler placed after the cache likewise cannot change an answer that
has already been served by the cache: place answer-affecting query
transformations before cache lookup.

NXDOMAIN and NODATA carrying an SOA use the smaller of the SOA RR TTL and
SOA.MINIMUM as their cache lifetime (RFC 2308). NXDOMAIN without an SOA is
not cached. Locally generated negative-response classification is retained
in new cache dumps so stats can still count cached local blocks correctly.
Older dumps are accepted, but cannot recover classification they never stored.

File-backed providers now take a file-state baseline **before** initial load.
Changes while that load is running are detected at the first poll. File content
hashes detect in-place edits preserving mtime and size. For files larger than
16 MiB, unchanged-metadata content is rehashed at most every 30 seconds to
avoid excessive repeated disk I/O. If a reload fails, the old matcher is
retained and the failed change is retried. An empty
or comment-only adblock rule file intentionally clears the matcher; a file
with invalid rules and no valid rules is rejected instead.

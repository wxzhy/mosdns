# Cache correctness and background refresh

The cache keys on the DNS question (including QCLASS), AD/CD/DO flags, and
canonical query name. Queries containing answer-affecting EDNS options,
including ECS, bypass the shared cache. A downstream operation that introduces
such an option also prevents the frontend, lazy refresh, and prefetch workers
from writing its result under an ordinary key.

When prefetch is enabled, each newly populated cache entry remembers its
producing sequence continuation, but **not the client's address or personal
query context**. Prefetch creates a neutral DNS question using the original
QNAME, QTYPE, QCLASS and DNSSEC flags. Entries loaded from a dump do not
restore executable continuations and cannot be proactively prefetched until
refreshed by a new frontend query.

**Policy boundary:** The default `scope: shared` keeps a common cache across
compatible sequences, including ordinary A and HTTPS auxiliary A lookups in
the SmartDNS examples. To isolate different sequence continuations using the
same cache plugin, explicitly set:

```yaml
args:
  scope: sequence
```

The cache does not partition by client IP: different clients querying the
same DNS question share cached answers, including in `scope: sequence` mode.
Sequence-scoped keys include the sequence identity and continuation position;
named sequences have restart-stable identities in cache dumps, whereas
anonymous programmatic sequences use process-local identities. The original
`sequence` key format remains compatible with earlier dumps.

**Policy boundary:** A globally shared cache, including its background
prefetch, must run *client-independent* response-producing logic. If an
installation intentionally serves client-specific or mark/KV-dependent
answers, separate the incompatible policies into different cache plugin
instances, or route to an appropriate independent cache before lookup.
An automatic prefetch cannot reconstruct arbitrary per-client routing context
from the DNS question alone. Do not enable prefetch on such a cache.

An ECS handler placed after the cache likewise cannot change an answer that
has already been served by the cache: place answer-affecting query
transformations before cache lookup.

NXDOMAIN and NODATA carrying an SOA use the smaller of the SOA RR TTL and
SOA.MINIMUM as their cache lifetime (RFC 2308). Both the first forwarded
response and later cache hits expose a SOA TTL no greater than this bound,
without mutating the original upstream response. NXDOMAIN without an SOA is
not cached. Locally generated negative-response classification is retained
in new cache dumps so stats can still count cached local blocks correctly.
Older dumps are accepted, but cannot recover classification they never stored.
Imported dumps are validated in full before committing any entries, including
checking cache-key question, type, class and scope encoding against the
serialized DNS response. Old pre-QCLASS dump keys are migrated when valid.

File-backed providers now take a file-state baseline **before** initial load.
Changes while that load is running are detected at the first poll. File content
hashes detect in-place edits preserving mtime and size. For files larger than
16 MiB, unchanged-metadata content is rehashed at most every 30 seconds to
avoid excessive repeated disk I/O. If a reload fails, the old matcher is
retained and the failed change is retried. An empty
or comment-only adblock rule file intentionally clears the matcher; a file
with invalid rules and no valid rules is rejected instead.

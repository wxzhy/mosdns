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

Lazy refresh and prefetch replace only the cache entry that triggered them.
A newer entry written while a refresh is running keeps its answer and metadata.

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

## Dynamic address targets

`ip_fallback` and `ip_replace` have no persistent address cache. A cache in
their `ip_source` chain stores the target DNS question, independently for A and
AAAA, so different original user questions can reuse the same target answer.
Without such a cache, each eligible rewrite resolves its domain targets again.
The plugin `timeout` bounds lookup work; cache `size` bounds entry capacity.
Neither setting specifies the cached answer's lifetime.

For positive answers, the normal cache lifetime is the minimum TTL across
Answer, Authority and Additional, excluding OPT. Hits subtract elapsed whole
seconds from each stored record's TTL. Positive answers with a minimum TTL of
zero are not cached. SERVFAIL currently has a five-second cache lifetime.

The final rewritten Answer is separately bounded by the remaining address and
CNAME lifetimes of targets that actually contribute unique addresses. Fallback
also applies its configured TTL and the original alias chain's applicable
lifetime; replacement also applies the original address/alias lifetime. Mixed
targets use the shortest applicable bound. For example, a cached target with
about 20 seconds left cannot produce a day-long fallback answer.

`lazy_cache_ttl` is total positive-entry retention from storage, not additional
time after the DNS TTL. During that retention, an expired answer may be returned
with a temporary TTL of five seconds while refreshing. Set it to zero to stop
using expired targets. Prefetch is optional and requires a positive remaining
lifetime below `prefetch_before_expire` and at least `prefetch_min_hits` hits;
it runs at the configured scan interval, so refresh before expiry is not
guaranteed. Target-query recursion guards survive both refresh mechanisms.

The cache stores DNS messages and timing, not complete response-snapshot
`ValidUntil` metadata. A target cache hit is analyzed from its returned TTL;
the rewrite then preserves applicable absolute deadlines within that execution.
An outer cache of final user responses can serve its stored answer directly,
bypassing another lookup, rewrite and speed selection on that hit.

See [the dynamic target guide](dynamic-ip-targets.md) for formulas, a dedicated
cache chain, ECS limitations and an offline example.

File-backed providers now take a file-state baseline **before** initial load.
Changes while that load is running are detected at the first poll. File content
hashes detect in-place edits preserving mtime and size. For files larger than
16 MiB, unchanged-metadata content is rehashed at most every 30 seconds to
avoid excessive repeated disk I/O. If a reload fails, the old matcher is
retained and the failed change is retried. An empty
or comment-only adblock rule file intentionally clears the matcher; a file
with invalid rules and no valid rules is rejected instead.

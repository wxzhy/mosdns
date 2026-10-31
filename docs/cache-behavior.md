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

**Policy boundary:** The cache remains intentionally shared across compatible
sequences, including the ordinary A lookup and HTTPS auxiliary A lookup in
the SmartDNS examples. The same query key reached through two incompatible
policies can still share an answer. Use separate cache plugin instances, or
arrange routing before the cache, if the policy must be isolated. An ECS
handler placed after the cache likewise cannot change an answer that has
already been served by the cache: place answer-affecting query transformations
before cache lookup.

NXDOMAIN and NODATA carrying an SOA use the smaller of the SOA RR TTL and
SOA.MINIMUM as their cache lifetime (RFC 2308). NXDOMAIN without an SOA is
not cached. Locally generated negative-response classification is retained
in new cache dumps so stats can still count cached local blocks correctly.
Older dumps are accepted, but cannot recover classification they never stored.

File-backed providers now take a file-state baseline **before** initial load.
Changes while that load is running are detected at the first poll. If a reload
fails, the old matcher is retained and the failed change is retried. An empty
or comment-only adblock rule file intentionally clears the matcher; a file
with invalid rules and no valid rules is rejected instead.

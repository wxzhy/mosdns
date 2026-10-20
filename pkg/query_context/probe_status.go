package query_context

// ProbeStatus records why a selector returned an address response. Unknown is
// distinct from Unmeasured: a raw response carries no evidence of selection.
// Failed requires every eligible address to have a completed failed probe;
// disabled, filtered, canceled, pending or queue-limited work is Unmeasured.
type ProbeStatus uint8

const (
	ProbeUnknown ProbeStatus = iota
	ProbeSucceeded
	ProbeFailed
	ProbeUnmeasured
)

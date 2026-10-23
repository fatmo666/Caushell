# State capacity

All retained safety objects count toward the same session budget, including
task state and background state. An object is `(scope, kind, name)`; another
candidate for the same object does not consume another object slot.

The default object exhaustion threshold is 32,768. The 16,384-background-object
workload therefore has room for its task state. The node, edge, candidate,
value-byte, history-payload-byte and request-byte limits remain independent.
Threshold equality exhausts the object/history budgets; zero is not unlimited.
Explicitly configured limits are not raised automatically.

`decision_trace.analysis_usage` records the projected graph counts, candidate
payload bytes, request bytes, limits and incomplete budgets before commitment.
Judge-only projections are not retained state. Payload bytes exclude graph
structure, serialized event copies and allocator overhead. Runtime memory and
persisted file sizes are measured separately.

Graph counters and object indexes are derived from retained facts and rebuilt
on snapshot recovery. Entry-state witnesses already present in history are
reused; actual writes and their request records remain. Candidate queries retain
earlier alternatives rather than replacing them with the latest value.

Replay frames read the shared entry snapshot directly and keep local writes separately.
Unset entries shadow the base map. Frame clones cannot change their parent.
Session summaries use copy-on-write variable maps with the same serialized form.

Exhaustion is sticky across approval, compaction and recovery. It yields Ask
unless another rule requires Deny; approval does not make incomplete history
complete. Capacity status and the final policy decision are separate results.

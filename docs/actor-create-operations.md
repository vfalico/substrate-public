# Durable suspended Actor Create operations

`CreateActorRequest.operation_id` optionally binds a host-authored canonical UUID
and the complete normalized Actor input to the original server-authored suspended
Create response. PostgreSQL commits that response, request hash, namespace UID and
Actor row in one transaction. Concurrent retries return the same original response.
Changed input/target/namespace generation refuses. The request field is generic;
it neither parses an execution requirement nor selects an enforcer.

The caller must durably record the UUID and original request BEFORE the RPC.
A lost reply can be retried without duplicate compute. `lookup_only=true` returns
the original response or NOT_FOUND and never creates compute: retirement/recovery
must use this form, then exact UID-checked stop. A normal Create replay after target
deletion returns the original identity; it never recreates the Actor or adopts its
replacement. Successful Create/lookup is cleanup identity only, NOT current status,
activation proof or permission to resume. Resume still requires exact UID and the
ordinary execution gate. Existing requests without operation_id retain behavior.
The optional persistence extension fails closed when unavailable.

Operation tombstones intentionally survive target deletion. No automatic expiry
or garbage collector is provided: erasing an uncertain operation could recreate
compute on a delayed retry. They retain original normalized actor metadata/policy
bytes under the existing service persistence trust boundary. Namespace deletion
or recreation refuses stale operation replay instead of granting new authority.
The usual Create authorization is still applied by the public gRPC middleware;
a UUID is an idempotence identity, not a bearer credential or cross-namespace grant.

Qualification: race tests cover actual PostgreSQL overlap, failed-create rollback,
changed inputs, target deletion and replacement; store-contract partitionability
covers insertion and lookup; public gRPC functional tests cover lookup-only absent,
first create, replay, changed policy, deletion, replacement and invalid UUID.
The functional tests use envtest/PostgreSQL and a fake worker that never resumes.
They are not kernel enforcement or process-crash qualification. The Sessions caller
must still implement and qualify pre-RPC durable operation retention separately.

## Atomic retirement barrier

`retire_operation=true` is mutually exclusive with lookup-only. Under the existing
Actor lease it atomically retires the operation and marks its original Actor
DELETING (only if the original UID still exists). If creation has not committed,
it installs an irreversible cancellation tombstone and returns an empty Actor.
If creation committed, it returns the original suspended response for exact
termination; this response does not claim the compute remains suspended now.
All later creating/lookup replays refuse, but retirement retries return the same
original cleanup identity. Resume explicitly refuses DELETING before native
side effects, including its second under-lease read. Replacement compute remains
untouched. Cleanup must then call the existing exact-UID DeleteActor workflow.
Tombstone success alone is not native termination or enforcement retirement.
The API remains protected by ordinary Create plus use-template authorization;
it grants no workload-side identity and adds no policy interpretation.

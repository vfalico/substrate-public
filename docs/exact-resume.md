# Optional exact Actor incarnation on Resume

ResumeActorRequest.actor_uid is an optional immutable incarnation precondition.
The owning Control verifies it before the already-running observation and again
under the existing Actor lease before any volume, worker assignment, restore or
running-state mutation. A mismatch returns Aborted. Empty preserves ordinary
name-based callers. This check is independent of execution-requirement format
and does not interpret policy or operate an enforcer.

This is a bounded port of the Sessions-fork correction commit
854b5a04024aa7b9f416e88dde09419f4ea5a32a onto the selected kagent
Substrate tree b95671ad7a07081fb95fabaf6241b37611975ce0.
Generated protobuf and validation files are included. Regenerate via the
repository hack/protoc.sh and hack/update/codegen.sh, using pinned generator
modules; the bounded original generation commands are retained in task evidence.

Regression scope: exact-UID side-effect refusal, running fast-path refusal,
matching control, existing Control and API validation tests. This does not add
durable Create-operation recovery or prove final native runtime acceptance.

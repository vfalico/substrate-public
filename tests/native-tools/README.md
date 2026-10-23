# Current kagent fork native Session qualification

Opt-in privileged integration only; no deployment. Use isolated task-owned
resources, never production. Serial execution required; see Sessions fork's
`tests/native-tools/README.md` for host assets and endpoint constraints.

Build this fork's `cmd/atelet`, `cmd/ateapi/internal/controlapi`,
`cmd/atenet/internal/router`, `cmd/ateom-microvm` test binaries as
`evidence/kagent-native-{atelet,control,router,microvm}.test` using `go test -c`.
Build kagent `go/core/internal/grpcserver` tests as `native-kagent.test` in a
Go workspace containing current kagent/go and this Substrate fork. Compile
`sessions_client.go.txt` in the Sessions module as `native-sessions-client`;
it is a deliberately separate harnesswire compute-qualification driver.
Use a native toolchat `harnessnode` as `native-tool-harnessnode`.

Set `EXECUTION_NATIVE_ATELET=1`, `EXECUTION_NATIVE_CONTROL=1`,
`EXECUTION_NATIVE_ROUTER=1`, `EXECUTION_NATIVE_KAGENT=1` and corresponding
`*_BINARY` paths. Run controller.py IMPLEMENTATION_ROOT NEW_RUN_ID. It expects
Guardd venv/object, Kata kernel/image and native harness/client under evidence.
Kagent public Session service uses real PostgreSQL and production workflow /
Substrate client with TLS to Control. Node/asset discovery and authentication
are explicitly test-owned fixtures, not cluster provisioning acceptance.

The test freezes a requirement in public Session Create and PostgreSQL, starts
compute through owning lifecycle before advertising governed READY, drives
real allowed + denied native tools and zero-model-call replay, and deletes the
exact Session through its public RPC. It requires receiver model/allow/deny
counts 3/1/0, native VMM shutdown, daemon exit 0, and no remaining BPF pins.
This is NOT kagent native A2A, public Kaimahi Suite evaluation, or hosted-model
quality acceptance. No injected status or canned compute replies.

For normal kagent regression set KUBEBUILDER_ASSETS to the installed envtest
etcd/kube-apiserver directory. Missing assets/skips are not passing evidence.

`boundary_crash_controller.py IMPLEMENTATION_ROOT NEW_RUN_ID` additionally
qualifies the real microVM boundary with abrupt SIGKILL of the exact owned
enforcement daemon after activation. It must restart against the same owned
protected socket directory and database, preserve pins, reject omitted-policy
checkpoint/restore drift, complete empty deny-all and bad-digest pre-release
cases, and retire all pins. Compile the boundary test binary under the name
used in this controller; host DNS echo and native guest probe remain prerequisites.

# Opt-in native tools / public Suite qualification

These are privileged, task-owned integration tests, not deployment scripts.
Never run on a production host or against an existing actor. No upstream writes.

The controller takes `IMPLEMENTATION_ROOT RUN_ID`; it expects sibling checkouts
under `sources/` (`guardd`, `sessions`, `kaimahi`, `substrate-sessions`) and a
prepared `evidence/` asset directory. `RUN_ID` must be new. It creates an isolated
Guardd database/socket/BPF-pin root and starts the owning-compute test binary.
The test owns PostgreSQL, RPC services, Envoy, network namespaces and Kata VMM.
No host firewall rules or inotify limits are changed. Ports, veth addresses and
numeric Envoy UID 60807 must be unused; run serially. The task uses 10.207.8.0/30
for a transparent namespace relay preserving mTLS, avoiding host CNI port 443.

Required host capabilities/assets: root, nested KVM, cloud-hypervisor v47,
Kata guest/kernel/assets, cgroup v2, bpffs/BPF, PostgreSQL, Envoy 1.34.4,
Python, iproute2, Go toolchain matching each checkout. `evidence/network.bpf.o`,
`native-tool-harnessnode`, `native-sessions-client` and the four compiled test
binaries must be built from these source trees. The controller uses the existing
Guardd venv at `IMPLEMENTATION_ROOT/venv`. Missing assets are failures, not skips.
`sessions_client.go.txt` is compiled in the Sessions module, not this module.

Compile test binaries with `go test -c` for `cmd/ateom-microvm`, `cmd/atelet`,
`cmd/ateapi/internal/controlapi`, `cmd/atenet/internal/router`, output names
`microvm-sessions-tools.test`, `native-atelet.test`, `native-control.test`,
`native-router.test` in evidence. Compile Kaimahi app tests with
`-tags nativeintegration`, using a temporary Go workspace including Kaimahi,
Sessions, Sessions integrations/substrate and substrate-sessions. Keep this
workspace separate from normal Kaimahi compatibility tests: adapter dependencies
select newer SDKs and intentionally change package hash inputs.

Set explicit `EXECUTION_NATIVE_ATELET=1`, `EXECUTION_NATIVE_CONTROL=1`,
`EXECUTION_NATIVE_ROUTER=1`, with corresponding `*_BINARY` absolute paths.
For public Kaimahi also set `EXECUTION_NATIVE_KAIMAHI=1` and
`EXECUTION_NATIVE_KAIMAHI_BINARY=.../native-kaimahi.test`. Run the controller
serially with `EXECUTION_PUBLIC_NATIVE_SCENARIO=allow`, `deny`, then `empty`.
Allowed case requires passing receipt + equivalent replay with zero model calls;
deny/empty require failed evaluation and no passing receipt. Receiver counters
must respectively equal model/allow/deny = 2/1/0, 1/0/0, 0/0/0. Without Kaimahi,
the Sessions native client exercises allowed, replay and denied turns: 3/1/0.

Evidence: controller output, compute.log, sessions-native-client.log,
tool-receiver.log, Control/atelet/router/Envoy logs, successful public receipt.
All runs require `COMPUTE_EXIT 0`, `DAEMON_EXIT 0`, `PINS_REMAIN []`, and native
VMM shutdown. Inspect exact residues after any failure; no broad cleanup.
Control uses real error/unknown-field interceptors but test-owned credentials,
node discovery and image asset lookup. This does not qualify cluster auth,
Kubernetes controllers, hosted-model quality, or public Orka/kagent acceptance.

`boundary_crash_controller.py IMPLEMENTATION_ROOT NEW_RUN_ID` additionally
qualifies the real microVM boundary with abrupt SIGKILL of the exact owned
enforcement daemon after activation. It must restart against the same owned
protected socket directory and database, preserve pins, reject omitted-policy
checkpoint/restore drift, complete empty deny-all and bad-digest pre-release
cases, and retire all pins. Compile the boundary test binary under the name
used in this controller; host DNS echo and native guest probe remain prerequisites.

# Runtime-owned harness control over stdio

A strict empty outbound ceiling cannot carry TCP readiness or harness replies.
`ControlStdioContainer` in the root-owned execution enforcer locator opts a
microVM worker into control over the selected prepared container's Kata-agent
stdin/stdout. The selection is worker configuration, not policy or workload
metadata. No network exception is installed. The actual container is prepared
non-running and exact whole-requirement activation still precedes StartContainer.

Example additional locator field: `"ControlStdioContainer":"probe"`. Use the
actual unique container name. Its ordinary harness must explicitly support
`RUNTIME_CONTROL_STDIO=1`. Unknown/missing selected container and a pre-supplied
selector refuse startup. stdout is reserved for bounded binary frames; log to
stderr. Ingress routes use fixed actor/listener selectors (169.254.17.2, port),
not packet sockets. Only the runtime opens streams; guest OPEN frames are invalid.
No outbound address dialing, command execution, host tools, or model proxy are
provided by this transport. Host-initiated application traffic and its responses
are an explicit authenticated runtime control boundary, not network authority.

The Kata-agent endpoint remains owned by the runtime, outside the workload. Do
not expose its vsock/ttrpc credentials or a host socket to the workload. Runtime
route reuse still requires exact lookup before opening a stream. Malformed frames,
unsolicited future ids, oversized frames or receive overflow close the transport;
64 active streams, 32KiB frames, 16 queued frames per stream. Canceled blocked OPEN
closes the exact channel, not enforcement. No fallback to TCP when configured.
Control loss cannot grant network authority; cleanup uses the separate owner
connection/journal. Protected executable restore/fork refusals are unchanged.

Policy-free workloads retain their ordinary transport. This is Linux Kata microVM
control only, not a universal runtime protocol, DNS grant, HTTP proxy, or general
filesystem/descriptor policy. See tests in internal/controlstdio and
cmd/ateom-microvm/control_stdio_linux_test.go. Public native acceptance is opt-in;
unit tests alone are not kernel/launch acceptance.

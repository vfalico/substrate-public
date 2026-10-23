//go:build linux

package kata

import (
	"context"
	"fmt"
	"io"

	agentpb "github.com/agent-substrate/substrate/cmd/ateom-microvm/internal/third_party/kata/agentpb"
)

// StdinWriter uses the runtime-owned agent API, never an address exposed to the
// workload. The exact container/exec ids were chosen by the runtime at prepare.
type StdinWriter struct {
	Context         context.Context
	Agent           *AgentClient
	Container, Exec string
}

func (w *StdinWriter) Write(data []byte) (int, error) {
	total := 0
	for len(data) > 0 {
		n := len(data)
		if n > 32768 {
			n = 32768
		}
		response := &agentpb.WriteStreamResponse{}
		err := w.Agent.client.Call(w.Context, "grpc.AgentService", "WriteStdin", &agentpb.WriteStreamRequest{ContainerId: w.Container, ExecId: w.Exec, Data: data[:n]}, response)
		if err != nil {
			return total, fmt.Errorf("agent WriteStdin: %w", err)
		}
		written := int(response.Len)
		if written <= 0 || written > n {
			return total, io.ErrShortWrite
		}
		total += written
		data = data[written:]
	}
	return total, nil
}

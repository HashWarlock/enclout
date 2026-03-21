package agent

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
)

// CLIPrompter prompts for approval via stdin/stdout.
type CLIPrompter struct {
	in  io.Reader
	out io.Writer
}

// NewCLIPrompter creates a CLIPrompter reading from in and writing to out.
func NewCLIPrompter(in io.Reader, out io.Writer) CLIPrompter {
	return CLIPrompter{
		in:  in,
		out: out,
	}
}

// Confirm prints a prompt and reads a y/N answer from the reader.
func (p CLIPrompter) Confirm(_ context.Context, req RequestSummary) (bool, error) {
	_, _ = fmt.Fprintf(p.out, "Approve connector request %s for %s? [y/N]: ", req.ID, req.ConnectorID)
	reader := bufio.NewReader(p.in)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes", nil
}

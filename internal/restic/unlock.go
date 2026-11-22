package restic

import (
	"bytes"
	"context"
	"io"
	"regexp"
	"strconv"
)

// restic unlock prints this line as plain text, also with --json.
var removedLocks = regexp.MustCompile(`successfully removed (\d+) locks?`)

// Unlock implements Runner. restic considers a lock stale when its process
// is gone (same host) or it was not refreshed for 30 minutes.
func (c *CLI) Unlock(ctx context.Context, dir string, password []byte, removeAll bool, log io.Writer) (int, error) {
	args := []string{"unlock"}
	if removeAll {
		args = append(args, "--remove-all")
	}
	var out bytes.Buffer
	if err := c.run(ctx, dir, password, args, io.MultiWriter(&out, log), log); err != nil {
		return 0, err
	}
	return parseUnlock(out.Bytes()), nil
}

// parseUnlock returns the number of removed locks; 0 when restic printed
// nothing (it is silent when there was nothing to remove).
func parseUnlock(out []byte) int {
	m := removedLocks.FindSubmatch(out)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(string(m[1]))
	return n
}

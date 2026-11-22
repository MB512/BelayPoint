package restic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Snapshot is one entry of "restic snapshots --json". Only the fields
// BelayPoint shows are decoded.
type Snapshot struct {
	ID       string    `json:"id"`
	ShortID  string    `json:"short_id"`
	Time     time.Time `json:"time"`
	Hostname string    `json:"hostname"`
	Username string    `json:"username"`
	Paths    []string  `json:"paths"`
	Tags     []string  `json:"tags"`
}

// Snapshots implements Runner. --no-lock: listing needs no lock and must
// not wait for (or block) a running backup.
func (c *CLI) Snapshots(ctx context.Context, dir string, password []byte) ([]Snapshot, error) {
	var out bytes.Buffer
	if err := c.run(ctx, dir, password, []string{"snapshots", "--no-lock"}, &out, nil); err != nil {
		return nil, err
	}
	return parseSnapshots(out.Bytes())
}

func parseSnapshots(data []byte) ([]Snapshot, error) {
	var list []Snapshot
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parsing restic snapshots output: %w", err)
	}
	return list, nil
}

package web

import (
	"github.com/MB512/belaypoint/internal/repos"
)

// Thresholds of the disk bar: from DiskLow the meter turns yellow, from
// DiskHigh red, and a warning is shown.
const (
	DiskLow  = 0.80
	DiskHigh = 0.90
)

type diskData struct {
	Total, Used, Free string
	// Raw values for <meter>.
	TotalBytes, UsedBytes, LowBytes, HighBytes int64
	Percent                                    string
	Full                                       bool
}

// disk reads the file system of the repository root (one statfs call, so
// it is done for every page). nil if it cannot be read.
func (s *server) disk() *diskData {
	u, err := repos.FSStat(s.ReposDir)
	if err != nil || u.Total <= 0 {
		if err != nil {
			s.Logger.Debug("disk usage", "err", err)
		}
		return nil
	}
	used := u.Used()
	return &diskData{
		Total: formatBytes(u.Total), Used: formatBytes(used), Free: formatBytes(u.Avail),
		TotalBytes: u.Total, UsedBytes: used,
		LowBytes:  int64(float64(u.Total) * DiskLow),
		HighBytes: int64(float64(u.Total) * DiskHigh),
		Percent:   percent(used, u.Total),
		Full:      float64(used) >= float64(u.Total)*DiskHigh,
	}
}

//go:build unix

package repos

import (
	"fmt"
	"syscall"
)

// FSStat returns the size and free space of the file system holding dir
// (statfs). Inside the container this is the NAS volume mounted at /repos.
func FSStat(dir string) (FSUsage, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return FSUsage{}, fmt.Errorf("statfs %s: %w", dir, err)
	}
	bs := uint64(st.Bsize) //nolint:gosec,unconvert // block size is positive; its type differs per platform
	return FSUsage{
		Total: int64(st.Blocks * bs), //nolint:gosec // volume sizes fit in int64
		Free:  int64(st.Bfree * bs),  //nolint:gosec // see above
		Avail: int64(st.Bavail * bs), //nolint:gosec // see above
	}, nil
}

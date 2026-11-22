//go:build !unix

package repos

import "errors"

// FSStat is only implemented on Unix (the container is Linux); this keeps
// the module building elsewhere.
func FSStat(string) (FSUsage, error) {
	return FSUsage{}, errors.ErrUnsupported
}

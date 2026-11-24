package web

import (
	"cmp"
	"net/http"
	"slices"
	"strconv"

	"github.com/MB512/belaypoint/internal/repos"
)

// maxUserSlots is the number of categorical colours (series-1..8 in
// style.css). Users beyond it are folded into "other users": a generated
// ninth colour would be indistinguishable from an existing one.
const maxUserSlots = 8

// minLabelShare is the smallest block of the segmented bar (share of the
// whole, in %) that gets its share printed inside; smaller blocks are
// named by the legend and the tooltip only.
const minLabelShare = 7.0

// storageData is the Storage page: the volume split per user and the
// repositories ranked by size.
type storageData struct {
	// Volume is nil when the file system cannot be read; the bar then
	// shows the backups only.
	Volume *diskData
	// Parts are the blocks of the segmented bar, in legend order: users
	// alphabetically (each with its fixed colour), then other data and
	// free space.
	Parts []storagePart
	Repos []storageRepo
	// Unmeasured counts present repositories without disk usage yet.
	Unmeasured int
	Backups    string
	Scanning   bool
}

// storagePart is one block of the segmented bar. X and W are the block's
// start and width in percent of the bar (SVG coordinates: the CSP allows
// no style attributes, so widths cannot be set with CSS).
type storagePart struct {
	Name, Size, Share string
	Class             string // series-1..8, other-users, other-data, free
	X, W              string
	Label             bool // the share fits into the block
	Repos             int  // users only
}

// storageRepo is one row of the ranked bar list.
type storageRepo struct {
	Path, Owner, Size, Share, Files, Measured string
	Class                                     string
	W                                         string // bar length in percent of the largest repository
}

func (s *server) storagePage(w http.ResponseWriter, r *http.Request) {
	list, err := s.Repos.ListRepos(r.Context())
	if err != nil {
		s.Logger.Error("listing repositories", "err", err)
		http.Error(w, "listing repositories failed; see the container log", http.StatusInternalServerError)
		return
	}
	var rows []repoRow
	for _, repo := range list {
		if repo.Missing {
			continue // its last usage is outdated
		}
		row := repoRow{Path: repo.Path, Owner: repos.Owner(repo.Path)}
		if repo.Usage != nil {
			row.Size = formatBytes(repo.Usage.Bytes)
			row.Bytes, row.Files = repo.Usage.Bytes, repo.Usage.Files
			row.Measured = repo.UsageTime.In(s.Location).Format("2006-01-02 15:04")
		}
		rows = append(rows, row)
	}
	d := storage(rows, s.disk())
	d.Scanning = s.Scanner.Scanning()
	s.render(w, http.StatusOK, "storage.html", page{
		Title: "Storage", CSRF: sessionFrom(r.Context()).CSRF, Storage: d,
	})
}

// storage computes the page from the present repositories and the volume
// (nil if unknown). It is separate from the handler so tests can feed it
// numbers directly.
func storage(rows []repoRow, vol *diskData) *storageData {
	owners, total := summarize(rows)
	d := &storageData{Volume: vol, Unmeasured: total.Unmeasured, Backups: total.Size}

	// Colours follow the user, never the rank: users get their slot in
	// alphabetical order, so a growing user keeps its colour.
	slices.SortFunc(owners, func(a, b ownerRow) int { return cmp.Compare(a.Name, b.Name) })
	class := map[string]string{}
	var rest ownerRow
	for i, o := range owners {
		if i < maxUserSlots {
			class[o.Name] = "series-" + strconv.Itoa(i+1)
			continue
		}
		class[o.Name] = "other-users"
		rest.Repos += o.Repos
		rest.Bytes += o.Bytes
	}

	// The whole is the volume's used + free space; without the volume it
	// is the backups alone. Used space smaller than the backups (quota,
	// file system reporting) must not push the blocks past 100 %.
	whole := total.Bytes
	var other, free int64
	if vol != nil {
		free = vol.TotalBytes - vol.UsedBytes
		whole = max(vol.UsedBytes, total.Bytes) + free
		other = max(vol.UsedBytes-total.Bytes, 0)
	}
	var x float64
	add := func(name, cls string, bytes int64, nRepos int) {
		if bytes <= 0 || whole <= 0 {
			return
		}
		w := float64(bytes) * 100 / float64(whole)
		d.Parts = append(d.Parts, storagePart{
			Name: name, Size: formatBytes(bytes), Share: percent(bytes, whole), Class: cls,
			X: pct(x), W: pct(w), Label: w >= minLabelShare, Repos: nRepos,
		})
		x += w
	}
	for i, o := range owners {
		if i < maxUserSlots {
			add(o.Name, class[o.Name], o.Bytes, o.Repos)
		}
	}
	add("other users", "other-users", rest.Bytes, rest.Repos)
	add("other data", "other-data", other, 0)
	add("free", "free", free, 0)

	// Repositories, largest first; bars scaled to the largest.
	ranked := slices.Clone(rows)
	slices.SortFunc(ranked, func(a, b repoRow) int {
		return cmp.Or(cmp.Compare(b.Bytes, a.Bytes), cmp.Compare(a.Path, b.Path))
	})
	for _, r := range ranked {
		row := storageRepo{
			Path: r.Path, Owner: r.Owner, Size: r.Size, Measured: r.Measured, Class: class[r.Owner],
		}
		if r.Size != "" {
			row.Share = percent(r.Bytes, total.Bytes)
			row.Files = strconv.FormatInt(r.Files, 10)
			if total.MaxBytes > 0 {
				row.W = pct(float64(r.Bytes) * 100 / float64(total.MaxBytes))
			}
		}
		d.Repos = append(d.Repos, row)
	}
	return d
}

// pct formats a percentage for an SVG coordinate ("12.345").
func pct(v float64) string { return strconv.FormatFloat(v, 'f', 3, 64) }

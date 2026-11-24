//
// Copyright 2026 sysbox community contributors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package mount

// Over-mounts of procfs/sysfs, for mounts from nested user namespaces
// (SBX-002, SBX-004). Pure functions, shared by sysbox-fs (the requester's
// view) and the nsenter build agent (the container's view).

import (
	"fmt"
	"strings"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
)

// OverMount is a mount on top of a procfs/sysfs mount (or of another
// over-mount), identified by its path relative to the procfs/sysfs mountpoint
// and its source (filesystem id + root within that filesystem).
type OverMount struct {
	Rel  string `json:"rel"`
	Dev  string `json:"dev"`
	Root string `json:"root"`
	RO   bool   `json:"ro"`
}

// OverMounts returns all the mounts in the tree on top of the topmost mount
// at base (e.g. "/proc", "/sys"), including over-mounts of over-mounts (e.g.
// /sys/devices/virtual/powercap over /sys/devices/virtual), in mountinfo
// order (parents before children). It returns nil if nothing is mounted at
// base.
func OverMounts(mounts []*domain.MountInfo, base string) []OverMount {
	baseID := -1
	for _, m := range mounts {
		if m.MountPoint == base {
			baseID = m.MountID // later entries are on top
		}
	}
	if baseID < 0 {
		return nil
	}

	var out []OverMount
	inTree := map[int]bool{baseID: true}
	prefix := strings.TrimSuffix(base, "/") + "/"
	for _, m := range mounts {
		if m.MountID == baseID || !inTree[m.ParentID] || !strings.HasPrefix(m.MountPoint, prefix) {
			continue
		}
		inTree[m.MountID] = true
		_, ro := m.Options["ro"]
		out = append(out, OverMount{
			Rel:  strings.TrimPrefix(m.MountPoint, strings.TrimSuffix(base, "/")),
			Dev:  m.MajorMinorVer,
			Root: m.Root,
			RO:   ro,
		})
	}
	return out
}

// CheckCovered verifies that a tree built with the 'built' over-mounts hides
// at least everything the requester's visible procfs/sysfs hides
// ('visible'): every visible over-mount must be in 'built', at the same
// relative path and from the same source. Otherwise the new mount would
// reveal something the kernel is protecting, so it's refused with EPERM, the
// errno the kernel returns for "mount too revealing".
func CheckCovered(visible, built []OverMount) error {
	type src struct{ dev, root string }
	have := make(map[string]src, len(built))
	for _, b := range built {
		have[b.Rel] = src{b.Dev, b.Root}
	}
	for _, v := range visible {
		if s, ok := have[v.Rel]; !ok || s != (src{v.Dev, v.Root}) {
			return fmt.Errorf("over-mount at %s is not reproduced by sysbox-fs: %w",
				v.Rel, syscall.EPERM)
		}
	}
	return nil
}

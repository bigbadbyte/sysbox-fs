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

package seccomp

// Procfs mounts from a nested user namespace (SBX-002, nestybox/sysbox#1062).
//
// The kernel refuses a new procfs in a mount namespace owned by a user
// namespace other than the container's, because the procfs visible there has
// locked over-mounts (sysbox-fs emulation, read-only and masked paths) and a
// fresh procfs would reveal what they hide ("mount too revealing").
//
// sysbox-fs builds the new procfs on the requester's behalf instead, in the
// container's mount namespace (where the mount is allowed) but in the
// requester's pid namespace, adds the same over-mounts the requester can
// already see on its /proc, locks the tree and moves it onto the target in
// the requester's mount namespace. The requester never gets a view that's
// less protected than the one it has (see checkOverMountsCovered).

import (
	"fmt"
	"strings"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
)

// procOverMount is a mount directly on top of a procfs mount, identified by
// its path relative to the procfs mountpoint and by its source (filesystem
// id + root within that filesystem).
type procOverMount struct {
	Rel  string
	Dev  string
	Root string
}

// procOverMounts returns the mounts directly on top of the topmost mount at
// base (e.g. "/proc"), in mountinfo order. It returns nil if nothing is
// mounted at base.
func procOverMounts(mounts []*domain.MountInfo, base string) []procOverMount {
	baseID := -1
	for _, m := range mounts {
		if m.MountPoint == base {
			baseID = m.MountID // later entries are on top
		}
	}
	if baseID < 0 {
		return nil
	}

	var out []procOverMount
	prefix := strings.TrimSuffix(base, "/") + "/"
	for _, m := range mounts {
		if m.ParentID != baseID || !strings.HasPrefix(m.MountPoint, prefix) {
			continue
		}
		out = append(out, procOverMount{
			Rel:  strings.TrimPrefix(m.MountPoint, strings.TrimSuffix(base, "/")),
			Dev:  m.MajorMinorVer,
			Root: m.Root,
		})
	}
	return out
}

// checkOverMountsCovered verifies that the tree sysbox-fs will build (with
// the 'built' over-mounts) hides at least everything the requester's visible
// procfs hides ('visible'): every visible over-mount must be in 'built', at
// the same relative path and from the same source. Otherwise the new mount
// would reveal something the kernel is protecting, so it's refused with
// EPERM, the errno the kernel returns for "mount too revealing".
func checkOverMountsCovered(visible, built []procOverMount) error {
	have := make(map[string]procOverMount, len(built))
	for _, b := range built {
		have[b.Rel] = b
	}
	for _, v := range visible {
		if b, ok := have[v.Rel]; !ok || b != v {
			return fmt.Errorf("procfs over-mount at %s is not reproduced by sysbox-fs: %w",
				v.Rel, syscall.EPERM)
		}
	}
	return nil
}

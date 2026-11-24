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

// Procfs/sysfs mounts from a nested user namespace (SBX-002, SBX-004,
// nestybox/sysbox#1062).
//
// The kernel refuses a new procfs/sysfs in a mount namespace owned by a user
// namespace other than the container's, because the one visible there has
// locked over-mounts (sysbox-fs emulation, read-only and masked paths) and a
// fresh instance would reveal what they hide ("mount too revealing").
//
// sysbox-fs builds the new instance on the requester's behalf instead, in the
// container's mount namespace (where the mount is allowed) but bound to the
// requester's pid (procfs) or net (sysfs) namespace, adds the same
// over-mounts the container has, locks the tree and moves it onto the target
// in the requester's mount namespace. The requester never gets a view that's
// less protected than the one it has (see mount.CheckCovered).

import (
	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/mount"
)

// procOverMount is mount.OverMount (kept as a local name for readability).
type procOverMount = mount.OverMount

func procOverMounts(mounts []*domain.MountInfo, base string) []procOverMount {
	return mount.OverMounts(mounts, base)
}

func checkOverMountsCovered(visible, built []procOverMount) error {
	return mount.CheckCovered(visible, built)
}

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

import (
	"sort"
	"strings"

	"github.com/nestybox/sysbox-fs/domain"
)

// mountSourceResolver maps a container-level mount path (e.g. "/proc/sys",
// one of the submounts sysbox places over procfs/sysfs) to a path that can be
// used as a bind-mount source inside the requesting process' mount namespace,
// when building a new procfs/sysfs mount at target.
//
// It exists because the requester may have pivot_root'ed into a filesystem
// where the container's original path no longer exists (e.g. bubblewrap
// pivots into a fresh tmpfs and the container's /proc ends up at
// /oldroot/proc; see nestybox/sysbox#1058).
type mountSourceResolver interface {
	Resolve(containerPath, target string) string
}

// containerMounts looks up the container's initial (immutable) mounts.
type containerMounts interface {
	LookupByMountpoint(mp string) *domain.MountInfo
}

// initialMounts adapts a container to containerMounts.
type initialMounts struct{ cntr domain.ContainerIface }

func (i initialMounts) LookupByMountpoint(mp string) *domain.MountInfo {
	return i.cntr.InitialMount(mp)
}

// newSourceResolver returns the resolver used for procfs/sysfs mount payloads.
func newSourceResolver(cntr domain.ContainerIface, requester requesterMounts) mountSourceResolver {
	var c containerMounts
	if cntr != nil {
		c = initialMounts{cntr}
	}
	return newMountinfoSourceResolver(c, requester)
}

// requesterMounts is the part of domain.MountInfoParserIface the resolver
// needs from the requester's mount table (Interface Segregation).
type requesterMounts interface {
	LookupByMountpoint(mp string) *domain.MountInfo
	LookupByFsID(fsID string) []*domain.MountInfo
}

// mountinfoSourceResolver identifies the container's mount at containerPath
// (filesystem id + root within that filesystem) and finds a mount of exactly
// the same filesystem subtree in the requester's mount table.
type mountinfoSourceResolver struct {
	container containerMounts
	requester requesterMounts
}

func newMountinfoSourceResolver(c containerMounts, r requesterMounts) *mountinfoSourceResolver {
	return &mountinfoSourceResolver{container: c, requester: r}
}

// Resolve returns the path under which the requester can reach the same mount
// the container has at containerPath. Copies at or below target are ignored,
// because the new mount will cover them.
//
// containerPath itself is returned when the requester sees that same mount
// there (the common case, which is unchanged), and also whenever no exact copy
// is found elsewhere. In that case the kernel decides, as it did before this
// resolver existed: it returns ENOENT if the path doesn't exist. Otherwise the
// shortest candidate path wins (deterministic). A different mount is never
// substituted: candidates must have the same filesystem id and root.
func (r *mountinfoSourceResolver) Resolve(containerPath, target string) string {
	want := r.containerMount(containerPath)
	if want == nil || r.requester == nil {
		return containerPath
	}

	var candidates []string
	for _, m := range r.requester.LookupByFsID(want.MajorMinorVer) {
		if !sameSubtree(m, want) || isAtOrBelow(m.MountPoint, target) || !r.isTopmost(m) {
			continue
		}
		if m.MountPoint == containerPath {
			return containerPath
		}
		candidates = append(candidates, m.MountPoint)
	}
	if len(candidates) == 0 {
		return containerPath
	}

	sort.Slice(candidates, func(i, j int) bool {
		if len(candidates[i]) != len(candidates[j]) {
			return len(candidates[i]) < len(candidates[j])
		}
		return candidates[i] < candidates[j]
	})
	return candidates[0]
}

func (r *mountinfoSourceResolver) containerMount(path string) *domain.MountInfo {
	if r.container == nil {
		return nil
	}
	return r.container.LookupByMountpoint(path)
}

// isTopmost reports whether m is what's visible at its mountpoint in the
// requester's namespace (an over-mount would make it unreachable there).
func (r *mountinfoSourceResolver) isTopmost(m *domain.MountInfo) bool {
	top := r.requester.LookupByMountpoint(m.MountPoint)
	return top == nil || top == m || sameSubtree(top, m)
}

func sameSubtree(a, b *domain.MountInfo) bool {
	return a.MajorMinorVer == b.MajorMinorVer && a.Root == b.Root
}

func isAtOrBelow(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

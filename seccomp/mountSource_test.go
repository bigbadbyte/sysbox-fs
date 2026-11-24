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
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
)

// fakeMountTable is a minimal mount table: it implements the two lookups the
// resolver needs, over a list of mountinfo entries.
type fakeMountTable []*domain.MountInfo

func (t fakeMountTable) LookupByMountpoint(mp string) *domain.MountInfo {
	var found *domain.MountInfo
	for _, m := range t {
		if m.MountPoint == mp {
			found = m // like the real parser: the last (topmost) entry wins
		}
	}
	return found
}

func (t fakeMountTable) LookupByFsID(id string) []*domain.MountInfo {
	var out []*domain.MountInfo
	for _, m := range t {
		if m.MajorMinorVer == id {
			out = append(out, m)
		}
	}
	return out
}

func mnt(mp, dev, root string) *domain.MountInfo {
	return &domain.MountInfo{MountPoint: mp, MajorMinorVer: dev, Root: root}
}

// The container's view, as set up by sysbox-runc / sysbox-fs.
var containerMountTable = fakeMountTable{
	mnt("/", "0:50", "/"),
	mnt("/proc", "0:60", "/"),
	mnt("/proc/sys", "0:70", "/proc/sys"),
	mnt("/proc/uptime", "0:70", "/proc/uptime"),
	mnt("/proc/bus", "0:60", "/bus"),   // read-only path
	mnt("/proc/kcore", "0:5", "/null"), // masked with /dev/null
	mnt("/proc/scsi", "0:80", "/"),     // masked with a tmpfs
	mnt("/sys", "0:90", "/"),
	mnt("/sys/kernel", "0:70", "/sys/kernel"),
}

// The requester's view after a bwrap-style pivot_root into a fresh tmpfs and
// an rbind of the old root to /newroot; the new procfs goes on /newroot/proc.
var pivotedMountTable = fakeMountTable{
	mnt("/", "0:99", "/"),
	mnt("/oldroot", "0:50", "/"),
	mnt("/oldroot/proc", "0:60", "/"),
	mnt("/oldroot/proc/sys", "0:70", "/proc/sys"),
	mnt("/oldroot/proc/uptime", "0:70", "/proc/uptime"),
	mnt("/oldroot/proc/bus", "0:60", "/bus"),
	mnt("/oldroot/proc/kcore", "0:5", "/null"),
	mnt("/oldroot/proc/scsi", "0:80", "/"),
	mnt("/oldroot/sys", "0:90", "/"),
	mnt("/oldroot/sys/kernel", "0:70", "/sys/kernel"),
	mnt("/newroot", "0:50", "/"),
	mnt("/newroot/proc", "0:60", "/"),
	mnt("/newroot/proc/sys", "0:70", "/proc/sys"),
	mnt("/newroot/proc/kcore", "0:5", "/null"),
}

func TestMountinfoSourceResolver(t *testing.T) {
	tests := []struct {
		name      string
		requester fakeMountTable
		source    string
		target    string // target of the new procfs/sysfs mount
		want      string
	}{
		{"common case keeps the container path", containerMountTable, "/proc/sys", "/root/proc", "/proc/sys"},
		{"common case masked path", containerMountTable, "/proc/kcore", "/root/proc", "/proc/kcore"},
		{"pivot: emulation mount found under old root", pivotedMountTable, "/proc/sys", "/newroot/proc", "/oldroot/proc/sys"},
		{"pivot: read-only path", pivotedMountTable, "/proc/bus", "/newroot/proc", "/oldroot/proc/bus"},
		{"pivot: masked path", pivotedMountTable, "/proc/kcore", "/newroot/proc", "/oldroot/proc/kcore"},
		{"pivot: tmpfs mask", pivotedMountTable, "/proc/scsi", "/newroot/proc", "/oldroot/proc/scsi"},
		{"pivot: sysfs", pivotedMountTable, "/sys/kernel", "/newroot/sys", "/oldroot/sys/kernel"},
		{
			"copies under the new mount's target are excluded (kernel decides)",
			fakeMountTable{mnt("/", "0:99", "/"), mnt("/newroot/proc/sys", "0:70", "/proc/sys")},
			"/proc/sys", "/newroot/proc", "/proc/sys",
		},
		{
			"no copy reachable: container path kept, kernel decides",
			fakeMountTable{mnt("/", "0:99", "/")},
			"/proc/sys", "/newroot/proc", "/proc/sys",
		},
		{
			"decoy at the container path with another device is not used",
			fakeMountTable{mnt("/proc/sys", "0:42", "/"), mnt("/old/proc/sys", "0:70", "/proc/sys")},
			"/proc/sys", "/x/proc", "/old/proc/sys",
		},
		{
			"decoy with the same device but another root is not used",
			fakeMountTable{mnt("/a/proc/sys", "0:70", "/proc/uptime")},
			"/proc/sys", "/x/proc", "/proc/sys",
		},
		{
			"several copies: shortest path wins, deterministically",
			fakeMountTable{
				mnt("/b/c/proc/sys", "0:70", "/proc/sys"),
				mnt("/z/proc/sys", "0:70", "/proc/sys"),
				mnt("/a/proc/sys", "0:70", "/proc/sys"),
			},
			"/proc/sys", "/x/proc", "/a/proc/sys",
		},
		{
			"target equal to a candidate is excluded too",
			fakeMountTable{mnt("/x/proc/sys", "0:70", "/proc/sys"), mnt("/y/proc/sys", "0:70", "/proc/sys")},
			"/proc/sys", "/x/proc/sys", "/y/proc/sys",
		},
		{
			"covered copy is skipped",
			fakeMountTable{
				mnt("/a/proc/sys", "0:70", "/proc/sys"),
				mnt("/a/proc/sys", "0:11", "/"), // something mounted on top
				mnt("/bb/proc/sys", "0:70", "/proc/sys"),
			},
			"/proc/sys", "/x/proc", "/bb/proc/sys",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newMountinfoSourceResolver(containerMountTable, tt.requester)
			if got := r.Resolve(tt.source, tt.target); got != tt.want {
				t.Fatalf("Resolve(%q, %q) = %q, want %q", tt.source, tt.target, got, tt.want)
			}
		})
	}
}

func TestMountinfoSourceResolverUnknownSource(t *testing.T) {
	r := newMountinfoSourceResolver(containerMountTable, pivotedMountTable)
	if got := r.Resolve("/proc/not-a-mount", "/newroot/proc"); got != "/proc/not-a-mount" {
		t.Fatalf("a path that isn't a container mount must be returned unchanged, got %q", got)
	}
}

func TestMountinfoSourceResolverNilTables(t *testing.T) {
	if got := newMountinfoSourceResolver(nil, nil).Resolve("/proc/sys", "/x/proc"); got != "/proc/sys" {
		t.Fatalf("with no mount tables the path must be returned unchanged, got %q", got)
	}
	if got := newMountinfoSourceResolver(containerMountTable, nil).Resolve("/proc/sys", "/x/proc"); got != "/proc/sys" {
		t.Fatalf("with no requester table the path must be returned unchanged, got %q", got)
	}
}

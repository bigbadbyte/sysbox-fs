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
	"reflect"
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
)

func mi(id, parent int, mp, dev, root string) *domain.MountInfo {
	return &domain.MountInfo{MountID: id, ParentID: parent, MountPoint: mp, MajorMinorVer: dev, Root: root}
}

// container's /proc with its over-mounts
var containerProc = []*domain.MountInfo{
	mi(1, 0, "/", "0:50", "/"),
	mi(10, 1, "/proc", "0:60", "/"),
	mi(11, 10, "/proc/sys", "0:70", "/proc/sys"),
	mi(12, 10, "/proc/uptime", "0:70", "/proc/uptime"),
	mi(13, 10, "/proc/kcore", "0:5", "/null"),
	mi(14, 10, "/proc/bus", "0:60", "/bus"),
}

func TestProcOverMounts(t *testing.T) {
	got := procOverMounts(containerProc, "/proc")
	want := []procOverMount{
		{Rel: "/sys", Dev: "0:70", Root: "/proc/sys"},
		{Rel: "/uptime", Dev: "0:70", Root: "/proc/uptime"},
		{Rel: "/kcore", Dev: "0:5", Root: "/null"},
		{Rel: "/bus", Dev: "0:60", Root: "/bus"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("procOverMounts = %+v\nwant %+v", got, want)
	}
	if got := procOverMounts(containerProc, "/nonexistent"); got != nil {
		t.Fatalf("no base mount: want nil, got %+v", got)
	}
}

func TestProcOverMountsUsesTopmostBase(t *testing.T) {
	m := append([]*domain.MountInfo{}, containerProc...)
	m = append(m,
		mi(20, 1, "/proc", "0:61", "/"), // a second procfs stacked on /proc
		mi(21, 20, "/proc/sys", "0:70", "/proc/sys"),
	)
	got := procOverMounts(m, "/proc")
	if len(got) != 1 || got[0].Rel != "/sys" {
		t.Fatalf("want only the over-mounts of the topmost /proc, got %+v", got)
	}
}

func TestCheckOverMountsCovered(t *testing.T) {
	built := procOverMounts(containerProc, "/proc")

	// requester sees the same set (paths may differ, e.g. after a pivot)
	if err := checkOverMountsCovered(built, built); err != nil {
		t.Fatalf("same set: %v", err)
	}
	// requester sees fewer over-mounts: fine, the new tree hides more
	if err := checkOverMountsCovered(built[:2], built); err != nil {
		t.Fatalf("subset: %v", err)
	}
	// requester's /proc hides something we would not: refuse
	extra := append(append([]procOverMount{}, built...), procOverMount{Rel: "/kmsg", Dev: "0:5", Root: "/null"})
	if err := checkOverMountsCovered(extra, built); err == nil {
		t.Fatal("extra over-mount on requester's /proc must be refused")
	}
	// same path but a different source: refuse
	diff := append([]procOverMount{}, built...)
	diff[0] = procOverMount{Rel: "/sys", Dev: "0:99", Root: "/"}
	if err := checkOverMountsCovered(diff, built); err == nil {
		t.Fatal("over-mount with a different source must be refused")
	}
}

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

func TestProcOverMountsRO(t *testing.T) {
	m := []*domain.MountInfo{mi(10, 1, "/proc", "0:60", "/"), mi(14, 10, "/proc/bus", "0:60", "/bus")}
	m[1].Options = map[string]string{"ro": "", "nosuid": ""}
	got := procOverMounts(m, "/proc")
	if len(got) != 1 || !got[0].RO {
		t.Fatalf("want /bus marked RO, got %+v", got)
	}
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

// container's /sys: over-mounts can be nested (powercap sits on the
// sysbox-fs mount at /sys/devices/virtual), and /sys/fs/cgroup is its own
// filesystem that the sandbox gets separately.
var containerSys = []*domain.MountInfo{
	mi(1, 0, "/", "0:50", "/"),
	mi(30, 1, "/sys", "0:80", "/"),
	mi(31, 30, "/sys/fs/cgroup", "0:23", "/"),
	mi(32, 30, "/sys/devices/virtual", "0:70", "/sys/devices/virtual"),
	mi(33, 30, "/sys/kernel", "0:70", "/sys/kernel"),
	mi(34, 32, "/sys/devices/virtual/powercap", "0:81", "/"),
	mi(35, 30, "/sys/firmware", "0:82", "/"),
}

func TestOverMountsNested(t *testing.T) {
	got := procOverMounts(containerSys, "/sys")
	want := []procOverMount{
		{Rel: "/fs/cgroup", Dev: "0:23", Root: "/"},
		{Rel: "/devices/virtual", Dev: "0:70", Root: "/sys/devices/virtual"},
		{Rel: "/kernel", Dev: "0:70", Root: "/sys/kernel"},
		{Rel: "/devices/virtual/powercap", Dev: "0:81", Root: "/"},
		{Rel: "/firmware", Dev: "0:82", Root: "/"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("procOverMounts(/sys) = %+v\nwant %+v", got, want)
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

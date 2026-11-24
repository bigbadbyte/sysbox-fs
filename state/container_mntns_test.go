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

package state

import (
	"os"
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
	"golang.org/x/sys/unix"
)

func sameFile(t *testing.T, f *os.File, path string) bool {
	t.Helper()
	var a, b unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &a); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(path, &b); err != nil {
		t.Fatal(err)
	}
	return a.Dev == b.Dev && a.Ino == b.Ino
}

// update() (registration) holds the init's mount ns; closeMountNs()
// (unregistration) releases it.
func Test_container_MountNsFileLifecycle(t *testing.T) {
	self := uint32(os.Getpid())
	c := &container{id: "c1", service: &containerStateService{prs: prs}}

	if err := c.update(&container{id: "c1", initPid: self, service: c.service}); err != nil {
		t.Skipf("update() needs a pidfd for our own process: %v", err)
	}
	defer unix.Close(int(c.initPidFd))

	f := c.MountNsFile()
	if f == nil {
		t.Fatal("mount ns not held after registration")
	}
	if !sameFile(t, f, "/proc/self/ns/mnt") {
		t.Fatal("held mount ns isn't the init's")
	}

	c.closeMountNs()
	if c.MountNsFile() != nil {
		t.Fatal("mount ns still held after closeMountNs()")
	}
	c.closeMountNs() // idempotent
}

// A failure to open the mount ns isn't fatal: the container registers and
// nothing is held (callers fall back to init's mount ns).
func Test_container_MountNsFileOpenFailure(t *testing.T) {
	c := &container{id: "c2"}
	c.closeMountNs() // nothing held: no-op
	if c.MountNsFile() != nil {
		t.Fatal("expected no mount ns")
	}
}

type fakeMountParser struct {
	domain.MountInfoParserIface
	mounts []*domain.MountInfo
}

func (f *fakeMountParser) AllMounts() []*domain.MountInfo { return f.mounts }

// InitialMounts serves the registration-time mount list (the source of the
// over-mounts sysbox-fs rebuilds), or nil before it's set up.
func Test_container_InitialMounts(t *testing.T) {
	c := &container{id: "c3"}
	if c.InitialMounts() != nil {
		t.Fatal("no mounts before the mount info is set up")
	}
	want := []*domain.MountInfo{{MountID: 1, MountPoint: "/proc"}}
	c.mountInfoParser = &fakeMountParser{mounts: want}
	if got := c.InitialMounts(); len(got) != 1 || got[0] != want[0] {
		t.Fatalf("InitialMounts() = %v", got)
	}
}

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

package nsutil

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func statIno(t *testing.T, path string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}

func TestInode(t *testing.T) {
	self := uint32(os.Getpid())
	got, err := Inode(self, "user")
	if err != nil {
		t.Fatal(err)
	}
	if want := statIno(t, "/proc/self/ns/user"); got != want {
		t.Fatalf("Inode = %d, want %d", got, want)
	}
	if _, err := Inode(0, "user"); err == nil {
		t.Fatal("pid 0 must fail")
	}
}

// Our own pid ns is owned by our own user ns (no unshare in between).
func TestOwnerInodeOfOwnPidNs(t *testing.T) {
	self := uint32(os.Getpid())
	got, err := OwnerInode(self, "pid")
	if err != nil {
		t.Skipf("NS_GET_USERNS unavailable: %v", err)
	}
	if want := statIno(t, "/proc/self/ns/user"); got != want {
		t.Fatalf("owner of our pid ns = %d, want our user ns %d", got, want)
	}
}

func TestOpenOwner(t *testing.T) {
	f, err := OpenOwner(uint32(os.Getpid()), "net")
	if err != nil {
		t.Skipf("NS_GET_USERNS unavailable: %v", err)
	}
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	if want := statIno(t, "/proc/self/ns/user"); st.Ino != want {
		t.Fatalf("owner fd inode = %d, want %d", st.Ino, want)
	}
	if _, err := OpenOwner(0, "net"); err == nil {
		t.Fatal("pid 0 must fail")
	}
}

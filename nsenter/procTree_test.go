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

package nsenter

// The procfs tree build/attach paths need root and namespaces; they're
// covered end to end by tests/syscall/mount/mount-procfs-userns.bats. These
// tests cover the parts that run unprivileged.

import (
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"golang.org/x/sys/unix"
)

func TestMountAttrs(t *testing.T) {
	tests := []struct {
		flags uint64
		want  int
	}{
		{0, 0},
		{unix.MS_RDONLY, unix.MOUNT_ATTR_RDONLY},
		{unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC,
			unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOEXEC},
		{unix.MS_RDONLY | unix.MS_RELATIME, unix.MOUNT_ATTR_RDONLY}, // others ignored
	}
	for _, tt := range tests {
		if got := mountAttrs(tt.flags); got != tt.want {
			t.Errorf("mountAttrs(%#x) = %#x, want %#x", tt.flags, got, tt.want)
		}
	}
}

func TestProcTreeErrorKeepsErrnoAndMessage(t *testing.T) {
	e := &NSenterEvent{}
	e.procTreeError(fmt.Errorf("fsopen proc: %w", syscall.ENOSYS))

	data, err := json.Marshal(*e.ResMsg)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Type    domain.NSenterMsgType `json:"message"`
		Payload fuse.IOerror          `json:"payload"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Type != domain.ErrorResponse || got.Payload.Code != syscall.ENOSYS ||
		got.Payload.Message != "fsopen proc: function not implemented" {
		t.Errorf("error response = %+v (%s)", got, data)
	}

	e.procTreeError(fmt.Errorf("no errno in here"))
	data, _ = json.Marshal(*e.ResMsg)
	_ = json.Unmarshal(data, &got)
	if got.Payload.Code != syscall.EIO {
		t.Errorf("non-errno error must map to EIO, got %v", got.Payload.Code)
	}
}

func TestProcTreeAttachWithoutFd(t *testing.T) {
	e := &NSenterEvent{
		treeFd: -1,
		ReqMsg: &domain.NSenterMessage{Payload: domain.ProcTreeAttachPayload{Target: "/x"}},
	}
	if err := e.processProcTreeAttachRequest(); err != nil {
		t.Fatal(err)
	}
	if e.ResMsg.Type != domain.ErrorResponse {
		t.Fatalf("want error response, got %+v", e.ResMsg)
	}
}

func TestIsProcTreeLocker(t *testing.T) {
	os.Unsetenv(procTreeLockerEnv)
	if IsProcTreeLocker() {
		t.Fatal("not a locker without the env var")
	}
	t.Setenv(procTreeLockerEnv, "/tmp/x")
	// fd 3 in a test binary is not our reply socket
	var st unix.Stat_t
	if unix.Fstat(3, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		if IsProcTreeLocker() {
			t.Fatal("not a locker without a socket on fd 3")
		}
	}
}

func TestRecvOneFd(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, b := os.NewFile(uintptr(pair[0]), "a"), os.NewFile(uintptr(pair[1]), "b")
	defer a.Close()
	defer b.Close()

	f, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := unix.Sendmsg(int(b.Fd()), []byte{1}, unix.UnixRights(int(f.Fd())), nil, 0); err != nil {
		t.Fatal(err)
	}
	fd, err := recvOneFd(a)
	if err != nil || fd < 0 {
		t.Fatalf("recvOneFd = %d, %v", fd, err)
	}
	unix.Close(fd)

	// no fd attached
	if err := unix.Sendmsg(int(b.Fd()), []byte{1}, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := recvOneFd(a); err == nil {
		t.Fatal("expected an error when no fd is sent")
	}
}

func TestSetDumpableRestores(t *testing.T) {
	before, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Skip(err)
	}
	restore, err := setDumpable()
	if err != nil {
		t.Fatal(err)
	}
	if now, _ := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); now != 1 {
		t.Errorf("dumpable = %d, want 1", now)
	}
	restore()
	if after, _ := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); after != before {
		t.Errorf("dumpable after restore = %d, want %d", after, before)
	}
}

func TestBoundedBuffer(t *testing.T) {
	b := &boundedBuffer{max: 5}
	n, err := b.Write([]byte("abc"))
	if n != 3 || err != nil {
		t.Fatal(n, err)
	}
	n, _ = b.Write([]byte("defgh"))
	if n != 5 || b.String() != "abcde" {
		t.Fatalf("got %q (n=%d)", b.String(), n)
	}
}

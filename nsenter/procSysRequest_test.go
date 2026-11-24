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

import (
	"encoding/json"
	"os"
	"strconv"
	"syscall"
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"golang.org/x/sys/unix"
)

func procSysEvent(t *testing.T, typ domain.NSenterMsgType, payload interface{}) *NSenterEvent {
	t.Helper()
	d, _ := fakeProcSys(t)
	return &NSenterEvent{
		procSysFd: int(d.Fd()),
		ReqMsg:    &domain.NSenterMessage{Type: typ, Payload: payload},
	}
}

func errno(t *testing.T, m *domain.NSenterMessage) syscall.Errno {
	t.Helper()
	if m.Type != domain.ErrorResponse {
		t.Fatalf("want an error response, got %+v", m)
	}
	data, _ := json.Marshal(*m)
	var got struct {
		Payload fuse.IOerror `json:"payload"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	return got.Payload.Code
}

func TestProcSysRequestRead(t *testing.T) {
	e := procSysEvent(t, domain.ReadFileRequest,
		domain.ReadFilePayload{File: "/proc/sys/net/ipv4/ip_forward", Len: 16})
	if !e.processProcSysRequest() {
		t.Fatal("must be handled with a /proc/sys fd")
	}
	if e.ResMsg.Type != domain.ReadFileResponse || string(e.ResMsg.Payload.([]byte)) != "1\n" {
		t.Fatalf("read response = %+v", e.ResMsg)
	}
}

func TestProcSysRequestWriteLookupDirLinkOpen(t *testing.T) {
	e := procSysEvent(t, domain.WriteFileRequest,
		domain.WriteFilePayload{File: "/proc/sys/net/ipv4/ip_forward", Data: []byte("0\n")})
	e.processProcSysRequest()
	if e.ResMsg.Type != domain.WriteFileResponse {
		t.Fatalf("write response = %+v", e.ResMsg)
	}

	e = procSysEvent(t, domain.LookupRequest, domain.LookupPayload{Entry: "/proc/sys/net"})
	e.processProcSysRequest()
	if fi, ok := e.ResMsg.Payload.(domain.FileInfo); e.ResMsg.Type != domain.LookupResponse || !ok || !fi.FisDir {
		t.Fatalf("lookup response = %+v", e.ResMsg)
	}

	e = procSysEvent(t, domain.ReadDirRequest, domain.ReadDirPayload{Dir: "/proc/sys/net/ipv4"})
	e.processProcSysRequest()
	if l, ok := e.ResMsg.Payload.([]domain.FileInfo); e.ResMsg.Type != domain.ReadDirResponse || !ok || len(l) != 1 {
		t.Fatalf("readdir response = %+v", e.ResMsg)
	}

	e = procSysEvent(t, domain.ReadLinkRequest, domain.ReadLinkPayload{Link: "/proc/sys/link"})
	e.processProcSysRequest()
	if e.ResMsg.Type != domain.ReadLinkResponse || e.ResMsg.Payload.(string) != "net/ipv4/ip_forward" {
		t.Fatalf("readlink response = %+v", e.ResMsg)
	}

	e = procSysEvent(t, domain.OpenFileRequest, domain.OpenFilePayload{
		File: "/proc/sys/net/ipv4/ip_forward", Flags: strconv.Itoa(unix.O_RDONLY), Mode: "0"})
	e.processProcSysRequest()
	if e.ResMsg.Type != domain.OpenFileResponse {
		t.Fatalf("open response = %+v", e.ResMsg)
	}
}

// Errors keep their errno (e.g. EACCES from the kernel's sysctl check),
// they aren't flattened to EINVAL/EIO.
func TestProcSysRequestErrnos(t *testing.T) {
	e := procSysEvent(t, domain.ReadFileRequest,
		domain.ReadFilePayload{File: "/proc/sys/nope", Len: 4})
	e.processProcSysRequest()
	if got := errno(t, e.ResMsg); got != syscall.ENOENT {
		t.Fatalf("errno = %v, want ENOENT", got)
	}
	if os.Geteuid() != 0 {
		e = procSysEvent(t, domain.WriteFileRequest,
			domain.WriteFilePayload{File: "/proc/sys/kernel_ro", Data: []byte("y")})
		e.processProcSysRequest()
		if got := errno(t, e.ResMsg); got != syscall.EACCES {
			t.Fatalf("errno = %v, want EACCES", got)
		}
	}
	e = procSysEvent(t, domain.OpenFileRequest, domain.OpenFilePayload{
		File: "/proc/sys/net", Flags: "bad", Mode: "0"})
	e.processProcSysRequest()
	if e.ResMsg.Type != domain.ErrorResponse {
		t.Fatalf("bad flags: want error, got %+v", e.ResMsg)
	}
}

// Without the fd (all regular requests), and for other request types, the
// regular handlers run.
func TestProcSysRequestNotHandled(t *testing.T) {
	e := &NSenterEvent{procSysFd: -1, ReqMsg: &domain.NSenterMessage{
		Type: domain.ReadFileRequest, Payload: domain.ReadFilePayload{File: "/proc/sys/x"}}}
	if e.processProcSysRequest() {
		t.Fatal("no fd: must not be handled")
	}
	e = procSysEvent(t, domain.MountSyscallRequest, nil)
	if e.processProcSysRequest() {
		t.Fatal("other request types must not be handled")
	}
}

// viaProcSys runs the regular handler only when the request isn't served
// through the fd.
func TestViaProcSys(t *testing.T) {
	ran := false
	regular := func() error { ran = true; return nil }

	e := procSysEvent(t, domain.ReadFileRequest,
		domain.ReadFilePayload{File: "/proc/sys/net/ipv4/ip_forward", Len: 4})
	if err := e.viaProcSys(regular); err != nil || ran {
		t.Fatalf("with fd: err %v, regular ran %v", err, ran)
	}
	e = &NSenterEvent{procSysFd: -1, ReqMsg: e.ReqMsg}
	if err := e.viaProcSys(regular); err != nil || !ran {
		t.Fatalf("without fd: err %v, regular ran %v", err, ran)
	}
}

// Events start without a /proc/sys fd; SetProcSysFd (the
// NSenterProcSysEventIface sysbox-fs uses) sets it.
func TestNewEventHasNoProcSysFd(t *testing.T) {
	ev := NewNSenterService().NewEvent(1, 0, 0, &domain.AllNSs, 0, nil, nil, false)
	if ev.(*NSenterEvent).procSysFd != -1 {
		t.Fatal("new events must not carry a /proc/sys fd")
	}
	pe, ok := ev.(domain.NSenterProcSysEventIface)
	if !ok {
		t.Fatal("NSenterEvent must implement NSenterProcSysEventIface")
	}
	pe.SetProcSysFd(7)
	if ev.(*NSenterEvent).procSysFd != 7 {
		t.Fatal("SetProcSysFd didn't set the fd")
	}
}

// Init's env handling: the fd number comes from the env var.
func TestProcSysFdFromEnv(t *testing.T) {
	t.Setenv(procSysFdEnv, "")
	if fd, err := procSysFdFromEnv(); err != nil || fd != -1 {
		t.Fatalf("unset: %d, %v", fd, err)
	}
	t.Setenv(procSysFdEnv, strconv.Itoa(agentProcSysFd))
	if fd, err := procSysFdFromEnv(); err != nil || fd != agentProcSysFd {
		t.Fatalf("set: %d, %v", fd, err)
	}
	t.Setenv(procSysFdEnv, "x")
	if _, err := procSysFdFromEnv(); err == nil {
		t.Fatal("bad value must fail")
	}
}

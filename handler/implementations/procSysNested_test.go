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

package implementations

import (
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
	"golang.org/x/sys/unix"
)

type fakeNsIDs struct {
	userns map[uint32]uint64 // pid -> user ns inode
	owner  map[uint32]uint64 // pid -> owner of its pid ns
	err    error
}

func (f fakeNsIDs) userNs(pid uint32) (uint64, error) {
	if f.err != nil {
		return 0, f.err
	}
	return f.userns[pid], nil
}

func (f fakeNsIDs) pidNsOwner(pid uint32) (uint64, error) {
	if f.err != nil {
		return 0, f.err
	}
	return f.owner[pid], nil
}

// init pid 10 is in the container's user ns 100 (owner of its pid ns);
// pid 20 is in a nested user ns 200; pid 30 is in the container's.
var testIDs = fakeNsIDs{
	userns: map[uint32]uint64{10: 100, 20: 200, 30: 100},
	owner:  map[uint32]uint64{10: 100},
}

func TestRouteFor(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		pid    uint32
		ids    fakeNsIDs
		nested bool
	}{
		{"container process, /proc/sys", "/proc/sys/net/ipv4/ip_forward", 30, testIDs, false},
		{"nested user ns, /proc/sys", "/proc/sys/net/ipv4/ip_forward", 20, testIDs, true},
		{"nested user ns, /proc/sys itself", "/proc/sys", 20, testIDs, true},
		// sysfs binds net entries to the mounter's net ns: keep the old path
		{"nested user ns, /sys", "/sys/class/net", 20, testIDs, false},
		{"nested user ns, other /proc", "/proc/uptime", 20, testIDs, false},
		{"not under /proc/sys", "/proc/sysrq-trigger", 20, testIDs, false},
		// on lookup errors, fall back to today's behaviour
		{"ns lookup error", "/proc/sys/kernel/hostname", 20, fakeNsIDs{err: errors.New("x")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := routeFor(tt.path, tt.pid, 10, tt.ids)
			if r.nested != tt.nested {
				t.Fatalf("nested = %v, want %v", r.nested, tt.nested)
			}
		})
	}
}

// The nested route: user ns joined LAST (the agent must not lose its
// rights over the requester's container-owned namespaces before joining
// them); the requester's mount ns joined (never sysbox-fs' host mounts in
// the requester's pid ns); no unshare and no fresh procfs mount.
func TestNestedRouteNamespaces(t *testing.T) {
	r := routeFor("/proc/sys/kernel/hostname", 20, 10, testIDs)
	want := []domain.NStype{
		domain.NStypeNet, domain.NStypeUts, domain.NStypeIpc,
		domain.NStypeCgroup, domain.NStypePid, domain.NStypeMount,
		domain.NStypeUser,
	}
	if !reflect.DeepEqual(r.namespaces, want) {
		t.Fatalf("namespaces = %v, want %v", r.namespaces, want)
	}
	if r.cloneFlags != 0 || r.mountProcfs || r.mountSysfs {
		t.Fatalf("nested route must not unshare/mount: %+v", r)
	}
}

// fakeEvent records what runAgent sets up and answers with a canned reply.
type fakeEvent struct {
	domain.NSenterEventIface
	procSysFd int
}

func (e *fakeEvent) SetProcSysFd(fd int) { e.procSysFd = fd }

type fakeNss struct {
	domain.NSenterServiceIface
	ev     *fakeEvent
	ns     []domain.NStype
	clone  uint32
	req    *domain.NSenterMessage
	res    *domain.NSenterMessage
	sendFd int // the /proc/sys fd at send time (must still be open)
}

func (s *fakeNss) NewEvent(pid, uid, gid uint32, ns *[]domain.NStype, clone uint32,
	req, res *domain.NSenterMessage, async bool) domain.NSenterEventIface {
	s.ev, s.ns, s.clone, s.req = &fakeEvent{procSysFd: -1}, *ns, clone, req
	return s.ev
}

func (s *fakeNss) SendRequestEvent(e domain.NSenterEventIface) error {
	s.sendFd = s.ev.procSysFd
	if s.sendFd >= 0 {
		if _, err := unix.FcntlInt(uintptr(s.sendFd), unix.F_GETFD, 0); err != nil {
			s.sendFd = -2 // closed too early
		}
	}
	return nil
}

func (s *fakeNss) ReceiveResponseEvent(e domain.NSenterEventIface) *domain.NSenterMessage {
	return s.res
}

type fakeHs struct {
	domain.HandlerServiceIface
	nss *fakeNss
}

func (h fakeHs) NSenterService() domain.NSenterServiceIface { return h.nss }

type fakeInit struct {
	domain.ProcessIface
	pid uint32
}

func (p fakeInit) Pid() uint32 { return p.pid }

type fakeCntr struct {
	domain.ContainerIface
	init domain.ProcessIface
}

func (c fakeCntr) InitProc() domain.ProcessIface { return c.init }

type fakeNode struct {
	domain.IOnodeIface
	path string
}

func (n fakeNode) Path() string { return n.path }

func withIDs(t *testing.T, ids nsIDs) {
	t.Helper()
	old := routeIDs
	routeIDs = ids
	t.Cleanup(func() { routeIDs = old })
}

// A nested-userns /proc/sys request: the agent gets a /proc/sys dir fd
// (open while the request is sent, closed after), the nested namespace list
// and no unshare/procfs mount.
func TestRunAgentNestedRoute(t *testing.T) {
	withIDs(t, testIDs)
	nss := &fakeNss{res: &domain.NSenterMessage{Type: domain.ReadFileResponse, Payload: []byte("1\n")}}
	req := &domain.HandlerRequest{Pid: 20, Container: fakeCntr{init: fakeInit{pid: 10}}}

	res, err := runAgent(fakeHs{nss: nss}, fakeNode{path: "/proc/sys/net/ipv4/ip_forward"}, req, nil,
		func(r passthroughRoute) *domain.NSenterMessage {
			return &domain.NSenterMessage{Type: domain.ReadFileRequest,
				Payload: &domain.ReadFilePayload{MountProcfs: r.mountProcfs}}
		})
	if err != nil || string(res.Payload.([]byte)) != "1\n" {
		t.Fatalf("runAgent = %+v, %v", res, err)
	}
	if !reflect.DeepEqual(nss.ns, nestedProcSysNSs) || nss.clone != 0 {
		t.Fatalf("ns = %v clone = %#x", nss.ns, nss.clone)
	}
	if nss.req.Payload.(*domain.ReadFilePayload).MountProcfs {
		t.Fatal("nested route must not mount a procfs")
	}
	if nss.sendFd < 0 {
		t.Fatalf("agent must get an open /proc/sys fd, got %d", nss.sendFd)
	}
	if _, err := unix.FcntlInt(uintptr(nss.sendFd), unix.F_GETFD, 0); err == nil {
		t.Fatal("the /proc/sys fd must be closed after the request")
	}
}

// Container processes and explicit namespace lists keep the old route and
// get no fd.
func TestRunAgentContainerRoute(t *testing.T) {
	withIDs(t, testIDs)
	build := func(r passthroughRoute) *domain.NSenterMessage {
		return &domain.NSenterMessage{Type: domain.ReadFileRequest}
	}
	for _, tt := range []struct {
		name   string
		pid    uint32
		ns     []domain.NStype
		wantNs []domain.NStype
	}{
		{"container process", 30, nil, domain.AllNSs},
		{"container process, explicit ns", 30, domain.AllNSsButUser, domain.AllNSsButUser},
		{"nested, explicit ns (shm sysctls)", 20, domain.AllNSsButUser, domain.AllNSsButUser},
	} {
		t.Run(tt.name, func(t *testing.T) {
			nss := &fakeNss{res: &domain.NSenterMessage{Type: domain.ReadFileResponse}}
			req := &domain.HandlerRequest{Pid: tt.pid, Container: fakeCntr{init: fakeInit{pid: 10}}}
			if _, err := runAgent(fakeHs{nss: nss}, fakeNode{path: "/proc/sys/kernel/shmmax"}, req, tt.ns, build); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(nss.ns, tt.wantNs) || nss.clone != unix.CLONE_NEWNS || nss.sendFd != -1 {
				t.Fatalf("ns %v clone %#x fd %d", nss.ns, nss.clone, nss.sendFd)
			}
		})
	}
}

// Error responses come back as errors; a failure to open /proc/sys fails
// the request (no silent fallback to the broken route).
func TestRunAgentErrors(t *testing.T) {
	withIDs(t, testIDs)
	build := func(r passthroughRoute) *domain.NSenterMessage { return &domain.NSenterMessage{} }
	req := &domain.HandlerRequest{Pid: 20, Container: fakeCntr{init: fakeInit{pid: 10}}}
	node := fakeNode{path: "/proc/sys/kernel/hostname"}

	nss := &fakeNss{res: &domain.NSenterMessage{Type: domain.ErrorResponse, Payload: errors.New("EACCES")}}
	if _, err := runAgent(fakeHs{nss: nss}, node, req, nil, build); err == nil {
		t.Fatal("error response must be returned as an error")
	}

	old := procSysDir
	procSysDir = func() (*os.File, error) { return nil, errors.New("no /proc/sys") }
	defer func() { procSysDir = old }()
	if _, err := runAgent(fakeHs{nss: &fakeNss{}}, node, req, nil, build); err == nil {
		t.Fatal("must fail when /proc/sys can't be opened")
	}
}

func TestIsAllNSs(t *testing.T) {
	short := []domain.NStype{domain.NStypeUser}
	reordered := append([]domain.NStype(nil), domain.AllNSs...)
	reordered[0], reordered[1] = reordered[1], reordered[0]
	for _, tt := range []struct {
		ns   []domain.NStype
		want bool
	}{
		{nil, true}, {domain.AllNSs, true}, {short, false}, {reordered, false},
		{domain.AllNSsButUser, false},
	} {
		if got := isAllNSs(tt.ns); got != tt.want {
			t.Errorf("isAllNSs(%v) = %v, want %v", tt.ns, got, tt.want)
		}
	}
}

// The real namespace identification (our own process: not nested).
func TestProcNsIDsOwnProcess(t *testing.T) {
	self := uint32(os.Getpid())
	nested, err := inNestedUserns(self, self, procNsIDs{})
	if err != nil {
		t.Skipf("NS_GET_USERNS unavailable: %v", err)
	}
	if nested {
		t.Fatal("our own process is not in a nested user ns relative to itself")
	}
}

// The container route is exactly today's behaviour.
func TestContainerRouteUnchanged(t *testing.T) {
	r := routeFor("/proc/sys/net/ipv4/ip_forward", 30, 10, testIDs)
	if !reflect.DeepEqual(r.namespaces, domain.AllNSs) ||
		r.cloneFlags != unix.CLONE_NEWNS || !r.mountProcfs || r.mountSysfs {
		t.Fatalf("container route changed: %+v", r)
	}
	r = routeFor("/sys/kernel/foo", 30, 10, testIDs)
	if !r.mountSysfs || r.mountProcfs || r.cloneFlags != unix.CLONE_NEWNS {
		t.Fatalf("sysfs route changed: %+v", r)
	}
}

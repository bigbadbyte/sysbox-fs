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

// Passthrough of /proc/sys for processes in nested user namespaces (SBX-006).
//
// The regular passthrough agent joins all of the requester's namespaces,
// user ns first, then mounts a fresh procfs. For a requester in a nested
// user ns (unshare -U, bwrap --unshare-user, inner Docker userns-remap) both
// steps fail: once in the nested user ns the agent may no longer join the
// requester's container-owned pid/ipc/... namespaces, and the nested user ns
// may not mount a procfs it doesn't own a pid ns for.
//
// Sysctl values and permission checks follow the *reader's* namespaces and
// credentials, not the procfs instance. So the agent gets a /proc/sys dir fd
// opened by sysbox-fs, joins the requester's namespaces with the user ns
// last (so it can still join those the container's user ns owns), becomes
// root of that user ns, and accesses the file relative to the fd. Reads show
// the requester's values; writes are allowed exactly when the kernel allows
// the requester (e.g. denied for a net sysctl of a net ns its user ns doesn't
// own).

import (
	"fmt"
	"os"
	"strings"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/nsutil"
	"golang.org/x/sys/unix"
)

// nsIDs identifies a process' user ns and the owner of its pid ns.
type nsIDs interface {
	userNs(pid uint32) (uint64, error)
	pidNsOwner(pid uint32) (uint64, error)
}

type procNsIDs struct{}

// routeIDs identifies requesters' namespaces (overridable in tests).
var routeIDs nsIDs = procNsIDs{}

func (procNsIDs) userNs(pid uint32) (uint64, error)     { return nsutil.Inode(pid, "user") }
func (procNsIDs) pidNsOwner(pid uint32) (uint64, error) { return nsutil.OwnerInode(pid, "pid") }

// The namespaces the nested route joins, in nsexec join order (netns first,
// user ns last). The requester's mount ns too: an agent in the requester's
// pid ns but sysbox-fs' mount ns would expose the host's mount table via
// /proc/<agent>/mountinfo (see the security note in domain/nsenter.go). No
// CLONE_NEWNS and no procfs mount: the /proc/sys fd is used instead, so the
// requester's sysbox-fs /proc/sys isn't recursed into.
var nestedProcSysNSs = []domain.NStype{
	domain.NStypeNet,
	domain.NStypeUts,
	domain.NStypeIpc,
	domain.NStypeCgroup,
	domain.NStypePid,
	domain.NStypeMount,
	domain.NStypeUser,
}

// passthroughRoute is how an nsenter agent reaches a passthrough resource.
type passthroughRoute struct {
	namespaces  []domain.NStype
	cloneFlags  uint32
	mountSysfs  bool
	mountProcfs bool
	nested      bool // access /proc/sys through the fd (see above)
}

func isProcSys(path string) bool {
	return path == "/proc/sys" || strings.HasPrefix(path, "/proc/sys/")
}

// inNestedUserns reports whether pid's user ns isn't the container's (the
// owner of init's pid ns: init's own user ns may itself be nested).
func inNestedUserns(pid, initPid uint32, ids nsIDs) (bool, error) {
	cntr, err := ids.pidNsOwner(initPid)
	if err != nil {
		return false, err
	}
	own, err := ids.userNs(pid)
	if err != nil {
		return false, err
	}
	return own != cntr, nil
}

// procSysDir opens sysbox-fs' own /proc/sys for the agent (overridable in
// tests).
var procSysDir = func() (*os.File, error) {
	return os.OpenFile("/proc/sys", os.O_RDONLY|unix.O_DIRECTORY, 0)
}

// agentEvent is an nsenter event for a passthrough request, plus whatever
// it needs closed after SendRequestEvent().
type agentEvent struct {
	ev    domain.NSenterEventIface
	route passthroughRoute
	close func()
}

// newAgentEvent creates the nsenter event for msg on node n by requester
// req. ns overrides the namespaces of the container route (the *WithNS
// handler variants); the nested route always uses its own list.
func newAgentEvent(
	h domain.HandlerServiceIface, n domain.IOnodeIface, req *domain.HandlerRequest,
	ns []domain.NStype, build func(passthroughRoute) *domain.NSenterMessage) (*agentEvent, error) {

	route := routeFor(n.Path(), req.Pid, initPid(req), routeIDs)
	if route.nested && !isAllNSs(ns) {
		// a handler asked for specific namespaces (e.g. all but the user ns
		// for non-namespaced shm sysctls): honour it, as before
		route = containerRoute(n.Path())
	}
	if !route.nested && ns != nil {
		route.namespaces = ns
	}
	nsList := route.namespaces
	ev := h.NSenterService().NewEvent(req.Pid, req.Uid, req.Gid, &nsList,
		route.cloneFlags, build(route), nil, false)
	ae := &agentEvent{ev: ev, route: route, close: func() {}}
	if !route.nested {
		return ae, nil
	}
	pe, ok := ev.(domain.NSenterProcSysEventIface)
	if !ok {
		return nil, fmt.Errorf("nsenter event can't carry a /proc/sys fd")
	}
	dir, err := procSysDir()
	if err != nil {
		return nil, err
	}
	pe.SetProcSysFd(int(dir.Fd()))
	ae.close = func() { dir.Close() }
	return ae, nil
}

func isAllNSs(ns []domain.NStype) bool {
	if ns == nil {
		return true
	}
	if len(ns) != len(domain.AllNSs) {
		return false
	}
	for i := range ns {
		if ns[i] != domain.AllNSs[i] {
			return false
		}
	}
	return true
}

// runAgent sends a passthrough request built by build for the chosen route
// and returns the agent's response (an error for error responses).
func runAgent(
	h domain.HandlerServiceIface, n domain.IOnodeIface, req *domain.HandlerRequest,
	ns []domain.NStype, build func(passthroughRoute) *domain.NSenterMessage) (*domain.NSenterMessage, error) {

	ae, err := newAgentEvent(h, n, req, ns, build)
	if err != nil {
		return nil, err
	}
	defer ae.close()
	nss := h.NSenterService()
	if err := nss.SendRequestEvent(ae.ev); err != nil {
		return nil, err
	}
	res := nss.ReceiveResponseEvent(ae.ev)
	if res.Type == domain.ErrorResponse {
		return nil, res.Payload.(error)
	}
	return res, nil
}

func initPid(req *domain.HandlerRequest) uint32 {
	if req.Container == nil || req.Container.InitProc() == nil {
		return 0
	}
	return req.Container.InitProc().Pid()
}

// routeFor picks the route for a request on path by process pid of the
// container whose init is initPid. Only /proc/sys from a nested user ns
// takes the new route; anything else (or any lookup error) keeps today's.
func routeFor(path string, pid, initPid uint32, ids nsIDs) passthroughRoute {
	if isProcSys(path) && initPid != 0 {
		if nested, err := inNestedUserns(pid, initPid, ids); err == nil && nested {
			return passthroughRoute{namespaces: nestedProcSysNSs, nested: true}
		}
	}
	return containerRoute(path)
}

// containerRoute is the regular passthrough route. The agent joins all of
// the requester's namespaces, including the mount ns, so it doesn't carry
// sysbox-fs' mounts into the container. Files under /proc or /sys are read
// from a fresh procfs/sysfs, so they pick up the container's resources (net
// devices, ...); to keep that mount invisible to the container, the agent
// unshares its mount ns right after joining (CLONE_NEWNS, applied by nsexec
// after the joins).
func containerRoute(path string) passthroughRoute {
	r := passthroughRoute{namespaces: domain.AllNSs}
	r.mountSysfs = strings.HasPrefix(path, "/sys/")
	r.mountProcfs = strings.HasPrefix(path, "/proc/")
	if r.mountSysfs || r.mountProcfs {
		r.cloneFlags = unix.CLONE_NEWNS
	}
	return r
}

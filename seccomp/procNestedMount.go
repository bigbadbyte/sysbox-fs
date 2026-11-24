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
	"fmt"
	"os"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"github.com/nestybox/sysbox-fs/nsutil"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// nestedKind describes a filesystem that needs the build-then-move treatment
// when mounted from a nested user ns: procfs and sysfs (the kernel's "mount
// too revealing" check applies to both).
type nestedKind struct {
	fsType string        // "proc" or "sysfs"
	base   string        // where the container has it: "/proc" or "/sys"
	ns     domain.NStype // the namespace a new instance is bound to
}

var (
	nestedProc  = nestedKind{"proc", "/proc", domain.NStypePid}
	nestedSysfs = nestedKind{"sysfs", "/sys", domain.NStypeNet}
)

// nsOwnerFunc returns the inode of the user ns owning namespace ns of pid.
type nsOwnerFunc func(pid uint32, ns domain.NStype) (domain.Inode, error)

// openNsOwner returns an fd for the user ns owning namespace ns of pid
// (NS_GET_USERNS).
func openNsOwner(pid uint32, ns domain.NStype) (*os.File, error) {
	return nsutil.OpenOwner(pid, ns)
}

// nsOwner implements nsOwnerFunc.
func nsOwner(pid uint32, ns domain.NStype) (domain.Inode, error) {
	return nsutil.OwnerInode(pid, ns)
}

// containerUserns returns the inode of the container's user ns: the owner of
// the container init's pid ns, which sysbox-runc creates together with it.
// The init's *current* user ns isn't reliable: init may have unshared a
// nested one itself (e.g. an `unshare -U ...` entrypoint).
func containerUserns(init domain.ProcessIface, owner nsOwnerFunc) (domain.Inode, error) {
	if init == nil {
		return 0, fmt.Errorf("container has no init process: %w", syscall.ESRCH)
	}
	return owner(init.Pid(), domain.NStypePid)
}

// inNestedUserns reports whether the process is in a user namespace other
// than the container's (e.g. bwrap --unshare-user, unshare -U).
func inNestedUserns(proc domain.ProcessIface, cntrUserns domain.Inode) (bool, error) {
	if proc == nil {
		return false, nil
	}
	pu, err := proc.UserNsInode()
	if err != nil {
		return false, err
	}
	return pu != cntrUserns, nil
}

// boundToNestedNs checks the kernel's rule for a new procfs/sysfs from a
// nested user ns: the namespace it's bound to (the requester's pid ns for
// procfs, net ns for sysfs) must be owned by the requester's user ns, or the
// mount is refused (mount_capable() / sysfs_init_fs_context()). Since the
// build agent runs as the container's root, sysbox-fs must apply it itself.
func (m *mountSyscallInfo) boundToNestedNs(k nestedKind) error {
	owner, err := m.tracer.service.nsOwner()(m.pid, k.ns)
	if err != nil {
		return err
	}
	pu, err := m.processInfo.UserNsInode()
	if err != nil {
		return err
	}
	if owner != pu {
		return fmt.Errorf("%s needs a %s ns owned by the requester's user ns: %w",
			k.fsType, k.ns, syscall.EPERM)
	}
	return nil
}

// isNestedMount reports whether the requester is in a nested user ns, so
// that a procfs/sysfs mount needs processNestedMount.
func (m *mountSyscallInfo) isNestedMount() (bool, error) {
	cu, err := containerUserns(m.cntr.InitProc(), m.tracer.service.nsOwner())
	if err != nil {
		return false, err
	}
	return inNestedUserns(m.processInfo, cu)
}

// processNestedMount mounts procfs or sysfs for a process in a nested user ns
// (see procNested.go): build a locked tree in the container's namespaces,
// then attach it in the requester's.
func (m *mountSyscallInfo) processNestedMount(
	k nestedKind, mip domain.MountInfoParserIface) (*sysResponse, error) {

	logrus.Debugf("Processing new %s mount from a nested user ns: %v", k.fsType, m)

	if err := m.boundToNestedNs(k); err != nil {
		logrus.Debugf("Refusing %s mount from nested user ns (pid %d): %v", k.fsType, m.pid, err)
		return m.tracer.createErrorResponse(m.reqId, syscall.EPERM), nil
	}

	build, err := m.nestedTreePayload(k, mip)
	if err != nil {
		return m.tracer.createErrorResponse(m.reqId, err), nil
	}

	fd, resp, err := m.buildTree(k, build)
	if resp != nil || err != nil {
		return resp, err
	}
	defer unix.Close(fd)

	return m.attachTree(k, fd)
}

// nestedTreePayload lists the over-mounts for the new tree: the ones on the
// container's base as set up by sysbox-runc (its initial mounts, recorded at
// registration; the same set the in-place path applies, plus nested ones),
// after checking that the requester's visible base hides nothing more.
//
// The container's *initial* mounts, not init's current ones: init may now be
// in (or share) a mount ns with extra over-mounts that the build agent, in
// the held container mount ns, can't reproduce. Listing those as "built"
// would make the guard pass and the new tree reveal what they hide.
func (m *mountSyscallInfo) nestedTreePayload(
	k nestedKind, mip domain.MountInfoParserIface) (*domain.ProcTreeBuildPayload, error) {

	initial := m.cntr.InitialMounts()
	if len(initial) == 0 {
		return nil, fmt.Errorf("container's initial mounts unknown: %w", syscall.EPERM)
	}

	built := procOverMounts(initial, k.base)
	if len(built) == 0 {
		return nil, fmt.Errorf("container has no %s over-mounts: %w", k.base, syscall.EPERM)
	}
	visible := procOverMounts(allMounts(mip), k.base)
	if err := checkOverMountsCovered(visible, built); err != nil {
		logrus.Infof("Refusing %s mount from nested user ns (pid %d): %v", k.fsType, m.pid, err)
		return nil, syscall.EPERM
	}

	// Note: the new root dir shows as nobody:nogroup inside the nested user
	// ns. Its owner is the container's root, which isn't mapped there; that
	// matches a container-mounted procfs/sysfs viewed from a nested user ns.
	p := &domain.ProcTreeBuildPayload{
		FsType: k.fsType,
		Base:   k.base,
		Flags:  m.Flags | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC,
	}
	for _, o := range built {
		p.OverMounts = append(p.OverMounts, o.Rel)
		if o.RO {
			p.RoMounts = append(p.RoMounts, o.Rel)
		}
	}
	return p, nil
}

// containerMountNs returns the container's mount ns for the build agent: the
// one held since registration, or nil to use init's current one. The latter
// is refused if init has moved to a mount ns owned by another user ns (its
// over-mounts would be locked there, and the build would fail or, worse,
// copy the wrong mounts).
func (m *mountSyscallInfo) containerMountNs() (*os.File, error) {
	if f := m.cntr.MountNsFile(); f != nil {
		return f, nil
	}
	svc := m.tracer.service
	init := m.cntr.InitProc()
	cu, err := svc.nsOwner()(init.Pid(), domain.NStypePid)
	if err != nil {
		return nil, err
	}
	mu, err := svc.nsOwner()(init.Pid(), domain.NStypeMount)
	if err != nil {
		return nil, err
	}
	if mu != cu {
		return nil, fmt.Errorf("container mount ns not held and init (pid %d) left it", init.Pid())
	}
	return nil, nil
}

// buildTree: agent in the container's user ns (passed by fd: no process may
// be left in it) + a private copy of the container's mount ns (CLONE_NEWNS),
// in the requester's pid ns (procfs) or net ns (sysfs), so the new instance
// shows the requester's processes or network devices.
func (m *mountSyscallInfo) buildTree(
	k nestedKind, p *domain.ProcTreeBuildPayload) (int, *sysResponse, error) {

	init := m.cntr.InitProc()
	userns, err := m.tracer.service.openNsOwner()(init.Pid(), domain.NStypePid)
	if err != nil {
		return -1, nil, err
	}
	defer userns.Close()

	mntns, err := m.containerMountNs()
	if err != nil {
		logrus.Infof("%s mount from nested user ns (pid %d): %v", k.fsType, m.pid, err)
		return -1, m.tracer.createErrorResponse(m.reqId, syscall.EPERM), nil
	}

	nss := m.tracer.service.nss
	// Also join a pid ns visible in the container's /proc (the agent needs
	// /proc/self): the requester's for procfs (k.ns), the container's for
	// sysfs. Without it the agent stays in sysbox-fs' pid ns.
	ns := []domain.NStype{domain.NStypeUser, k.ns, domain.NStypeMount}
	if k.ns != domain.NStypePid {
		ns = append(ns, domain.NStypePid)
	}
	event := nss.NewEvent(init.Pid(), 0, 0, &ns, unix.CLONE_NEWNS,
		&domain.NSenterMessage{Type: domain.ProcTreeBuildRequest, Payload: p}, nil, false)

	te, ok := event.(domain.NSenterTreeEventIface)
	if !ok {
		return -1, nil, fmt.Errorf("nsenter event can't carry a %s tree", k.fsType)
	}
	te.SetNamespaceFile(domain.NStypeUser, userns)
	if mntns != nil {
		te.SetNamespaceFile(domain.NStypeMount, mntns)
	}
	te.SetNamespacePid(k.ns, m.pid)

	if err := nss.SendRequestEvent(event); err != nil {
		return -1, nil, err
	}
	res := nss.ReceiveResponseEvent(event)
	if res.Type == domain.ErrorResponse {
		ioerr := res.Payload.(fuse.IOerror)
		logrus.Infof("%s tree build for pid %d failed: %s", k.fsType, m.pid, ioerr.Message)
		return -1, m.tracer.createErrorResponse(m.reqId, ioerr.Code), nil
	}
	if te.TreeFd() < 0 {
		return -1, nil, fmt.Errorf("%s tree build returned no fd", k.fsType)
	}
	return te.TreeFd(), nil, nil
}

// attachTree: agent in the requester's user and mount namespaces moves the
// tree onto the target. Only these two: the tree is already bound to the
// right pid/net ns, and the requester's other namespaces may be owned by its
// nested user ns or by the container's; nsexec joins the user ns last, so
// some of those joins fail with EPERM (e.g. the container-owned pid ns of
// `unshare -Um`).
func (m *mountSyscallInfo) attachTree(k nestedKind, fd int) (*sysResponse, error) {
	nss := m.tracer.service.nss
	ns := []domain.NStype{domain.NStypeUser, domain.NStypeMount}
	event := nss.NewEvent(m.pid, m.uid, m.gid, &ns, 0,
		&domain.NSenterMessage{
			Type:    domain.ProcTreeAttachRequest,
			Payload: &domain.ProcTreeAttachPayload{Target: m.Target},
		}, nil, false)

	te, ok := event.(domain.NSenterTreeEventIface)
	if !ok {
		return nil, fmt.Errorf("nsenter event can't carry a %s tree", k.fsType)
	}
	te.SetTreeFd(fd)

	if err := nss.SendRequestEvent(event); err != nil {
		return nil, err
	}
	res := nss.ReceiveResponseEvent(event)
	if res.Type == domain.ErrorResponse {
		ioerr := res.Payload.(fuse.IOerror)
		logrus.Infof("%s tree attach for pid %d failed: %s", k.fsType, m.pid, ioerr.Message)
		return m.tracer.createErrorResponse(m.reqId, ioerr.Code), nil
	}
	return m.tracer.createSuccessResponse(m.reqId), nil
}

// allMounts returns the parser's mounts in mountinfo order.
func allMounts(mip domain.MountInfoParserIface) []*domain.MountInfo {
	if mip == nil {
		return nil
	}
	return mip.AllMounts()
}

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
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// inNestedUserns reports whether the process is in a user namespace other
// than the container's (e.g. bwrap --unshare-user, unshare -U).
func inNestedUserns(proc, cntrInit domain.ProcessIface) (bool, error) {
	if proc == nil || cntrInit == nil {
		return false, nil
	}
	pu, err := proc.UserNsInode()
	if err != nil {
		return false, err
	}
	cu, err := cntrInit.UserNsInode()
	if err != nil {
		return false, err
	}
	return pu != cu, nil
}

// processNestedProcMount mounts procfs for a process in a nested user ns
// (see procNested.go): build a locked tree in the container's namespaces,
// then attach it in the requester's.
func (m *mountSyscallInfo) processNestedProcMount(
	mip domain.MountInfoParserIface) (*sysResponse, error) {

	logrus.Debugf("Processing new procfs mount from a nested user ns: %v", m)

	build, err := m.nestedProcTreePayload(mip)
	if err != nil {
		return m.tracer.createErrorResponse(m.reqId, err), nil
	}

	fd, resp, err := m.buildProcTree(build)
	if resp != nil || err != nil {
		return resp, err
	}
	defer unix.Close(fd)

	return m.attachProcTree(fd)
}

// nestedProcTreePayload lists the over-mounts for the new procfs: the ones
// on the container's /proc (the same set processProcMount applies), after
// checking that the requester's visible /proc hides nothing more.
func (m *mountSyscallInfo) nestedProcTreePayload(
	mip domain.MountInfoParserIface) (*domain.ProcTreeBuildPayload, error) {

	init := m.cntr.InitProc()
	if init == nil {
		return nil, syscall.EPERM
	}
	cmip, err := m.tracer.service.mts.NewMountInfoParser(m.cntr, init, true, true, false)
	if err != nil {
		return nil, err
	}

	built := procOverMounts(allMounts(cmip), "/proc")
	if len(built) == 0 {
		return nil, fmt.Errorf("container has no /proc over-mounts: %w", syscall.EPERM)
	}
	visible := procOverMounts(allMounts(mip), "/proc")
	if err := checkOverMountsCovered(visible, built); err != nil {
		logrus.Infof("Refusing procfs mount from nested user ns (pid %d): %v", m.pid, err)
		return nil, syscall.EPERM
	}

	// Note: the procfs root dir shows as nobody:nogroup inside the nested user
	// ns. Its owner is the container's root, which isn't mapped there. That
	// matches a procfs mounted by the container and then viewed from a nested
	// user ns, and chown can't change a procfs root (EPERM).
	p := &domain.ProcTreeBuildPayload{
		Flags: m.Flags | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC,
	}
	for _, o := range built {
		p.OverMounts = append(p.OverMounts, o.Rel)
		if info := cmip.GetInfo("/proc" + o.Rel); info != nil && cmip.IsRoMount(info) {
			p.RoMounts = append(p.RoMounts, o.Rel)
		}
	}
	return p, nil
}

// buildProcTree: agent in the container's user + mount ns (a private copy,
// CLONE_NEWNS), in the requester's pid ns (so the procfs shows its pids).
func (m *mountSyscallInfo) buildProcTree(
	p *domain.ProcTreeBuildPayload) (int, *sysResponse, error) {

	init := m.cntr.InitProc()
	nss := m.tracer.service.nss
	ns := []domain.NStype{domain.NStypeUser, domain.NStypePid, domain.NStypeMount}
	event := nss.NewEvent(init.Pid(), 0, 0, &ns, unix.CLONE_NEWNS,
		&domain.NSenterMessage{Type: domain.ProcTreeBuildRequest, Payload: p}, nil, false)

	te, ok := event.(domain.NSenterTreeEventIface)
	if !ok {
		return -1, nil, fmt.Errorf("nsenter event can't carry a procfs tree")
	}
	te.SetNamespacePid(domain.NStypePid, m.pid)

	if err := nss.SendRequestEvent(event); err != nil {
		return -1, nil, err
	}
	res := nss.ReceiveResponseEvent(event)
	if res.Type == domain.ErrorResponse {
		ioerr := res.Payload.(fuse.IOerror)
		logrus.Infof("procfs tree build for pid %d failed: %s", m.pid, ioerr.Message)
		return -1, m.tracer.createErrorResponse(m.reqId, ioerr.Code), nil
	}
	if te.TreeFd() < 0 {
		return -1, nil, fmt.Errorf("procfs tree build returned no fd")
	}
	return te.TreeFd(), nil, nil
}

// attachProcTree: agent in the requester's user and mount namespaces moves
// the tree onto the target. Only these two: the tree already has the right
// pid ns, and the requester's other namespaces may be owned by its nested user
// ns or by the container's; nsexec joins the user ns last, so some of those
// joins fail with EPERM (e.g. the container-owned pid ns of `unshare -Um`).
func (m *mountSyscallInfo) attachProcTree(fd int) (*sysResponse, error) {
	nss := m.tracer.service.nss
	ns := []domain.NStype{domain.NStypeUser, domain.NStypeMount}
	event := nss.NewEvent(m.pid, m.uid, m.gid, &ns, 0,
		&domain.NSenterMessage{
			Type:    domain.ProcTreeAttachRequest,
			Payload: &domain.ProcTreeAttachPayload{Target: m.Target},
		}, nil, false)

	te, ok := event.(domain.NSenterTreeEventIface)
	if !ok {
		return nil, fmt.Errorf("nsenter event can't carry a procfs tree")
	}
	te.SetTreeFd(fd)

	if err := nss.SendRequestEvent(event); err != nil {
		return nil, err
	}
	res := nss.ReceiveResponseEvent(event)
	if res.Type == domain.ErrorResponse {
		ioerr := res.Payload.(fuse.IOerror)
		logrus.Infof("procfs tree attach for pid %d failed: %s", m.pid, ioerr.Message)
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

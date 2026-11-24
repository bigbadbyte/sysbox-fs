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

// Agent side of procfs mounts from nested user namespaces (SBX-002).
//
// Build (agent in the container's mount + user ns, requester's pid ns):
//   1. a private copy of the container's mount ns (nsexec unshares it
//      before the Go runtime starts: CloneFlags = CLONE_NEWNS), so nothing
//      leaks into the container's mount table;
//   2. fsopen/fsmount a procfs (it gets our pid ns: the requester's);
//   3. attach it to a temporary dir, bind the over-mounts from /proc onto it;
//   4. lock it: a child in a new user ns + mount ns (copy_mnt_ns() marks
//      every copied mount MNT_LOCKED) clones it with open_tree(OPEN_TREE_CLONE|
//      AT_RECURSIVE), which preserves MNT_LOCKED, and hands the fd back;
//   5. return the locked, detached tree fd to sysbox-fs (SCM_RIGHTS).
//
// Attach (agent in the requester's user + mount ns): move_mount(fd, target).
//
// Step 4 is required: attaching into the nested mount ns does *not* lock the
// tree (verified on kernels 6.8 and 7.2), and an unlocked tree would let the
// requester unmount the over-mounts and see the bare procfs.
//
// Requires the new mount API (fsopen/fsmount/open_tree/move_mount, Linux
// >= 5.2). On older kernels the build fails (ENOSYS), which is reported to
// the requester like the kernel's own refusal used to be.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"golang.org/x/sys/unix"
)

// Env var that turns a "sysbox-fs nsenter" re-exec into the tree locker.
const procTreeLockerEnv = "_SYSBOXFS_PROCTREE_LOCKER"

// procTreeError reports err to sysbox-fs. IOerror only carries an errno for
// bare syscall errors, so unwrap it (the full message is still sent).
func (e *NSenterEvent) procTreeError(err error) error {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		errno = syscall.EIO
	}
	e.ResMsg = &domain.NSenterMessage{
		Type: domain.ErrorResponse,
		Payload: &fuse.IOerror{
			RcvError: errno,
			Message:  err.Error(),
		},
	}
	return nil
}

func (e *NSenterEvent) processProcTreeBuildRequest() error {
	p := e.ReqMsg.Payload.(domain.ProcTreeBuildPayload)

	fd, err := buildLockedProcTree(p)
	if err != nil {
		return e.procTreeError(err)
	}

	e.fileDescr = append(e.fileDescr, fd)
	e.ResMsg = &domain.NSenterMessage{Type: domain.ProcTreeBuildResponse, Payload: ""}
	return nil
}

func (e *NSenterEvent) processProcTreeAttachRequest() error {
	p := e.ReqMsg.Payload.(domain.ProcTreeAttachPayload)

	if e.treeFd < 0 {
		return e.procTreeError(syscall.EBADF)
	}
	err := unix.MoveMount(e.treeFd, "", unix.AT_FDCWD, p.Target, unix.MOVE_MOUNT_F_EMPTY_PATH)
	unix.Close(e.treeFd)
	if err != nil {
		return e.procTreeError(err)
	}

	e.ResMsg = &domain.NSenterMessage{Type: domain.ProcTreeAttachResponse, Payload: ""}
	return nil
}

func buildLockedProcTree(p domain.ProcTreeBuildPayload) (int, error) {
	fsType, base, err := treeKind(p)
	if err != nil {
		return -1, err
	}

	// Our mount ns is a private copy (see above); make sure no mount event
	// propagates back to the container's.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return -1, fmt.Errorf("make / private: %w", err)
	}

	tmp, err := os.MkdirTemp("", "sysbox-"+fsType+"-")
	if err != nil {
		return -1, err
	}
	defer os.Remove(tmp)

	if err := mountFsAt(fsType, tmp, p.Flags); err != nil {
		return -1, err
	}
	defer unix.Unmount(tmp, unix.MNT_DETACH)

	if err := applyOverMounts(tmp, base, p); err != nil {
		return -1, err
	}

	// The locker re-execs us via /proc/self/exe, and Go writes its uid_map via
	// /proc/<pid>, so for procfs /proc must show our pid ns: cover it with the
	// new tree. For sysfs we stay in the container's pid ns, so its /proc is
	// right as is.
	if fsType == "proc" {
		if err := overmountProc(tmp); err != nil {
			return -1, err
		}
	}
	return lockTree(tmp)
}

// treeKind returns the filesystem type and container base path for p;
// only procfs and sysfs are supported (the ones with locked over-mounts).
func treeKind(p domain.ProcTreeBuildPayload) (string, string, error) {
	switch {
	case p.FsType == "" || p.FsType == "proc":
		return "proc", "/proc", nil
	case p.FsType == "sysfs":
		return "sysfs", "/sys", nil
	}
	return "", "", fmt.Errorf("unsupported filesystem %q: %w", p.FsType, syscall.EINVAL)
}

func mountFsAt(fsType, dir string, flags uint64) error {
	fsfd, err := unix.Fsopen(fsType, unix.FSOPEN_CLOEXEC)
	if err != nil {
		return fmt.Errorf("fsopen %s: %w", fsType, err)
	}
	defer unix.Close(fsfd)
	if err := unix.FsconfigCreate(fsfd); err != nil {
		return fmt.Errorf("fsconfig create: %w", err)
	}

	mfd, err := unix.Fsmount(fsfd, unix.FSMOUNT_CLOEXEC, mountAttrs(flags))
	if err != nil {
		return fmt.Errorf("fsmount %s (%s): %w", fsType, nsDesc(), err)
	}
	defer unix.Close(mfd)

	if err := unix.MoveMount(mfd, "", unix.AT_FDCWD, dir, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return fmt.Errorf("attach %s: %w", fsType, err)
	}
	return nil
}

// nsDesc describes our namespaces, for error messages (our /proc may be
// from another pid ns, in which case the links don't resolve).
func nsDesc() string {
	var out []string
	for _, ns := range []string{"user", "mnt", "pid", "net"} {
		l, err := os.Readlink("/proc/thread-self/ns/" + ns)
		if err != nil {
			l = "?"
		}
		out = append(out, ns+"="+l)
	}
	return strings.Join(out, " ")
}

// mountAttrs maps mount(2) flags to MOUNT_ATTR_* values.
func mountAttrs(flags uint64) int {
	attrs := 0
	for ms, ma := range map[uint64]int{
		unix.MS_RDONLY: unix.MOUNT_ATTR_RDONLY,
		unix.MS_NOSUID: unix.MOUNT_ATTR_NOSUID,
		unix.MS_NODEV:  unix.MOUNT_ATTR_NODEV,
		unix.MS_NOEXEC: unix.MOUNT_ATTR_NOEXEC,
	} {
		if flags&ms != 0 {
			attrs |= ma
		}
	}
	return attrs
}

// applyOverMounts binds each over-mount from the container's base (e.g.
// /sys/kernel) onto the same path in the new tree at dir. Binds are not
// recursive: nested over-mounts are listed (parents first) and bound
// separately, exactly as the container has them.
func applyOverMounts(dir, base string, p domain.ProcTreeBuildPayload) error {
	for _, rel := range p.OverMounts {
		dst := filepath.Join(dir, rel)
		if err := unix.Mount(filepath.Join(base, rel), dst, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind %s%s: %w", base, rel, err)
		}
	}
	for _, rel := range p.RoMounts {
		dst := filepath.Join(dir, rel)
		flags := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY |
			unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
		if err := unix.Mount("", dst, "", flags, ""); err != nil {
			return fmt.Errorf("remount ro %s: %w", rel, err)
		}
	}
	return nil
}

func overmountProc(src string) error {
	fd, err := unix.OpenTree(unix.AT_FDCWD, src,
		unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_RECURSIVE)
	if err != nil {
		return fmt.Errorf("open_tree %s: %w", src, err)
	}
	defer unix.Close(fd)
	if err := unix.MoveMount(fd, "", unix.AT_FDCWD, "/proc", unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return fmt.Errorf("cover /proc: %w", err)
	}
	return nil
}

// lockTree runs the locker (this binary, re-executed in a new user + mount
// ns) and returns the locked, detached tree fd it sends back.
func lockTree(dir string) (int, error) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	ours := os.NewFile(uintptr(pair[0]), "locker-parent")
	theirs := os.NewFile(uintptr(pair[1]), "locker-child")
	defer ours.Close()

	// /proc is now our pid ns' procfs (overmountProc), so /proc/self/exe
	// resolves to this binary even though its path isn't visible in this
	// mount ns.
	cmd := exec.Command("/proc/self/exe", "nsenter")
	cmd.Env = []string{procTreeLockerEnv + "=" + dir}
	cmd.ExtraFiles = []*os.File{theirs} // fd 3
	var stderr strings.Builder
	cmd.Stderr = &stderr
	// New user ns (container root mapped to root, so the locker keeps
	// CAP_SYS_ADMIN for open_tree(OPEN_TREE_CLONE)) + new mount ns.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}},
		GidMappingsEnableSetgroups: false,
	}

	// Go writes the child's /proc/<pid>/{uid,gid}_map from here. nsexec made
	// us non-dumpable, which makes those files owned by root of the initial
	// user ns (EACCES for us), and the child inherits that until exec. Like
	// nsexec's update_uidmap(), be dumpable just while the child is set up.
	restore, err := setDumpable()
	if err != nil {
		theirs.Close()
		return -1, err
	}
	err = cmd.Start()
	restore()
	theirs.Close()
	if err != nil {
		return -1, fmt.Errorf("start tree locker: %w", err)
	}

	fd, rerr := recvOneFd(ours)
	werr := cmd.Wait()
	if rerr != nil {
		return -1, fmt.Errorf("tree locker: %v (exit: %v: %s)", rerr, werr,
			strings.TrimSpace(stderr.String()))
	}
	return fd, nil
}

// IsProcTreeLocker reports whether this process was started as the locker by
// a procfs tree build agent (env var set and fd 3 is the reply socket).
func IsProcTreeLocker() bool {
	if os.Getenv(procTreeLockerEnv) == "" {
		return false
	}
	var st unix.Stat_t
	return unix.Fstat(3, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFSOCK
}

// RunProcTreeLocker runs in a new user ns and a mount ns copied from the
// builder's across that user ns boundary, so the kernel has marked the copied
// tree MNT_LOCKED. It clones the tree (preserving MNT_LOCKED) and sends its
// fd on fd 3.
func RunProcTreeLocker() error {
	sock := os.NewFile(3, "locker-child")
	defer sock.Close()

	fd, err := unix.OpenTree(unix.AT_FDCWD, os.Getenv(procTreeLockerEnv),
		unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_RECURSIVE)
	if err != nil {
		return fmt.Errorf("open_tree: %w", err)
	}
	defer unix.Close(fd)
	return unix.Sendmsg(int(sock.Fd()), []byte{1}, unix.UnixRights(fd), nil, 0)
}

// setDumpable makes this process dumpable and returns a function restoring
// the previous setting.
func setDumpable() (func(), error) {
	prev, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("get dumpable: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0); err != nil {
		return nil, fmt.Errorf("set dumpable: %w", err)
	}
	return func() { _ = unix.Prctl(unix.PR_SET_DUMPABLE, uintptr(prev), 0, 0, 0) }, nil
}

func recvOneFd(sock *os.File) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(int(sock.Fd()), buf, oob, unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		return -1, err
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		return -1, fmt.Errorf("no fd received (%v)", err)
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		return -1, fmt.Errorf("bad fd message (%v)", err)
	}
	return fds[0], nil
}

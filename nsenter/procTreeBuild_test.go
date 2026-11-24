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

// Tests of buildLockedProcTree (the privileged agent path).
//
// SAFETY: buildLockedProcTree changes mount propagation of "/" and mounts
// over /proc, which is only harmless in a throwaway mount ns. So the test
// never calls it in the test process: it re-executes the test binary into a
// new *unprivileged* user ns + new mount ns (+ pid or net ns), and the child
// first verifies that its mount and user namespaces differ from the
// parent's, refusing to run otherwise. No root is needed, and nothing in
// the caller's mount table can change, even if a test fails.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
	"golang.org/x/sys/unix"
)

const (
	treeTestChildEnv  = "_SYSBOXFS_TREE_TEST_CHILD" // "proc" or "sysfs"
	treeTestParentEnv = "_SYSBOXFS_TREE_TEST_PARENT_NS"
	treeTestFileEnv   = "_SYSBOXFS_TREE_TEST_FILE"
	treeTestOK        = "TREE-CHILD-OK"
)

func TestMain(m *testing.M) {
	// Re-executed as the tree locker by lockTree() (/proc/self/exe nsenter).
	if IsProcTreeLocker() {
		if err := RunProcTreeLocker(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	// Re-executed by runTreeChild() into throwaway namespaces.
	if kind := os.Getenv(treeTestChildEnv); kind != "" {
		if err := treeChild(kind); err != nil {
			fmt.Println("child:", err)
			os.Exit(1)
		}
		fmt.Println(treeTestOK)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestBuildLockedProcTree(t *testing.T) {
	out := runTreeChild(t, "proc", syscall.CLONE_NEWPID)
	if !strings.Contains(out, treeTestOK) {
		t.Fatalf("child failed:\n%s", out)
	}
}

func TestBuildLockedSysfsTree(t *testing.T) {
	out := runTreeChild(t, "sysfs", syscall.CLONE_NEWNET)
	if !strings.Contains(out, treeTestOK) {
		t.Fatalf("child failed:\n%s", out)
	}
}

func TestTreeKindRejectsOtherFilesystems(t *testing.T) {
	if _, _, err := treeKind(domain.ProcTreeBuildPayload{FsType: "tmpfs"}); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("treeKind(tmpfs) = %v, want EINVAL", err)
	}
	if fs, base, _ := treeKind(domain.ProcTreeBuildPayload{}); fs != "proc" || base != "/proc" {
		t.Fatalf("default kind = %s %s", fs, base)
	}
}

// runTreeChild re-executes the test binary in a new unprivileged user ns
// (our uid mapped to root) + mount ns + extra, and returns its output.
func runTreeChild(t *testing.T, kind string, extra uintptr) string {
	t.Helper()
	mask := filepath.Join(t.TempDir(), "mask")
	if err := os.WriteFile(mask, []byte("masked\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(),
		treeTestChildEnv+"="+kind,
		treeTestParentEnv+"="+nsIDs(),
		treeTestFileEnv+"="+mask)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | extra,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Skipf("unprivileged user namespaces unavailable: %v", err)
	}
	return string(out)
}

func nsIDs() string {
	user, _ := os.Readlink("/proc/self/ns/user")
	mnt, _ := os.Readlink("/proc/self/ns/mnt")
	return user + " " + mnt
}

// treeChild runs in the throwaway namespaces.
func treeChild(kind string) error {
	if parent := os.Getenv(treeTestParentEnv); parent == "" || nsIDs() == parent ||
		strings.Fields(parent)[1] == strings.Fields(nsIDs())[1] {
		return fmt.Errorf("refusing: not in a fresh mount + user ns (%s vs %s)", nsIDs(), parent)
	}
	// Our private copy of the mount ns: keep any mount event from
	// propagating out before we set up the base over-mount.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make / private: %w", err)
	}
	if kind == "proc" {
		return procChild()
	}
	return sysfsChild()
}

func procChild() error {
	// Our own procfs on /proc (we're pid 1 of a new pid ns), with a masked
	// file and a directory to make read-only, like sysbox-runc's setup.
	if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount own procfs: %w", err)
	}
	if err := unix.Mount(os.Getenv(treeTestFileEnv), "/proc/uptime", "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("mask /proc/uptime: %w", err)
	}
	if err := unix.Mount("/proc/sys", "/proc/sys", "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind /proc/sys: %w", err)
	}

	fd, err := buildLockedProcTree(domain.ProcTreeBuildPayload{
		FsType:     "proc",
		Flags:      unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC,
		OverMounts: []string{"sys", "uptime"},
		RoMounts:   []string{"sys"},
	})
	if err != nil {
		return fmt.Errorf("build: %w", err)
	}
	dir, err := attachAt(fd)
	if err != nil {
		return err
	}

	if b, err := os.ReadFile(filepath.Join(dir, "uptime")); err != nil || string(b) != "masked\n" {
		return fmt.Errorf("over-mount not reproduced: %q, %v", b, err)
	}
	if self, err := os.Readlink(filepath.Join(dir, "self")); err != nil || self != "1" {
		return fmt.Errorf("tree must show our pid ns (self=%q, %v)", self, err)
	}
	if err := checkReadOnly(filepath.Join(dir, "sys")); err != nil {
		return err
	}
	return checkLocked(filepath.Join(dir, "uptime"))
}

func sysfsChild() error {
	// A sysfs for our new net ns on /sys, with a masked file.
	if err := unix.Mount("sysfs", "/sys", "sysfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount own sysfs: %w", err)
	}
	if err := unix.Mount(os.Getenv(treeTestFileEnv), "/sys/kernel/uevent_seqnum", "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("mask uevent_seqnum: %w", err)
	}

	fd, err := buildLockedProcTree(domain.ProcTreeBuildPayload{
		FsType:     "sysfs",
		Flags:      unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC,
		OverMounts: []string{"kernel/uevent_seqnum"},
	})
	if err != nil {
		return fmt.Errorf("build: %w", err)
	}
	dir, err := attachAt(fd)
	if err != nil {
		return err
	}

	f := filepath.Join(dir, "kernel/uevent_seqnum")
	if b, err := os.ReadFile(f); err != nil || string(b) != "masked\n" {
		return fmt.Errorf("over-mount not reproduced: %q, %v", b, err)
	}
	return checkLocked(f)
}

// attachAt attaches the tree fd at a new temp dir (what the attach agent
// does at the requester's target).
func attachAt(fd int) (string, error) {
	defer unix.Close(fd)
	dir, err := os.MkdirTemp("", "tree-test-")
	if err != nil {
		return "", err
	}
	if err := unix.MoveMount(fd, "", unix.AT_FDCWD, dir, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return "", fmt.Errorf("attach: %w", err)
	}
	return dir, nil
}

func checkReadOnly(path string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return err
	}
	if st.Flags&unix.ST_RDONLY == 0 {
		return fmt.Errorf("%s must be read-only (flags %#x)", path, st.Flags)
	}
	return nil
}

// checkLocked: the over-mount must not be removable (MNT_LOCKED), or the
// masked file underneath would be revealed.
func checkLocked(path string) error {
	err := unix.Unmount(path, 0)
	if err == nil {
		return fmt.Errorf("over-mount %s is not locked (unmount succeeded)", path)
	}
	if !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.EPERM) {
		return fmt.Errorf("unmount %s: unexpected %v", path, err)
	}
	return nil
}

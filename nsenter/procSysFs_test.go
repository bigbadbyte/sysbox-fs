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
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// A fake /proc/sys tree in a temp dir (the dir fd semantics are the same).
func fakeProcSys(t *testing.T) (*os.File, string) {
	t.Helper()
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "net/ipv4"), 0755))
	must(os.WriteFile(filepath.Join(root, "net/ipv4/ip_forward"), []byte("1\n"), 0644))
	must(os.WriteFile(filepath.Join(root, "kernel_ro"), []byte("x\n"), 0444))
	must(os.Symlink("net/ipv4/ip_forward", filepath.Join(root, "link")))
	outside := filepath.Join(t.TempDir(), "secret")
	must(os.WriteFile(outside, []byte("secret\n"), 0644))
	must(os.Symlink(outside, filepath.Join(root, "escape")))
	d, err := os.Open(root)
	must(err)
	t.Cleanup(func() { d.Close() })
	return d, root
}

func TestProcSysFsRel(t *testing.T) {
	for in, want := range map[string]string{
		"/proc/sys":                     ".",
		"/proc/sys/":                    ".",
		"/proc/sys/net/ipv4/ip_forward": "net/ipv4/ip_forward",
	} {
		got, err := procSysRel(in)
		if err != nil || got != want {
			t.Errorf("procSysRel(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"/proc/uptime", "/sys/x", "/proc/sysrq-trigger", "/proc/sys/../1/environ",
		"/proc/sys/net/../kernel/hostname", "/proc/sys/./net", "/proc/sys//net",
	} {
		if _, err := procSysRel(bad); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("procSysRel(%q): want EINVAL, got %v", bad, err)
		}
	}
}

func TestProcSysFsReadWrite(t *testing.T) {
	d, root := fakeProcSys(t)
	fs := procSysFs{dir: int(d.Fd())}

	data, err := fs.readAt("/proc/sys/net/ipv4/ip_forward", 0, 16)
	if err != nil || string(data) != "1\n" {
		t.Fatalf("read = %q, %v", data, err)
	}
	if err := fs.writeAt("/proc/sys/net/ipv4/ip_forward", 0, []byte("0\n")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "net/ipv4/ip_forward")); string(b) != "0\n" {
		t.Fatalf("write didn't land: %q", b)
	}
	// symlinks within the tree are followed
	if data, err := fs.readAt("/proc/sys/link", 0, 16); err != nil || string(data) != "0\n" {
		t.Fatalf("read via in-tree link = %q, %v", data, err)
	}
}

// Nothing outside the dir fd is reachable: not via symlinks, not via "..".
func TestProcSysFsStaysBeneath(t *testing.T) {
	d, _ := fakeProcSys(t)
	fs := procSysFs{dir: int(d.Fd())}

	if _, err := fs.readAt("/proc/sys/escape", 0, 16); err == nil {
		t.Fatal("absolute symlink out of the tree must not be followed")
	}
	if _, err := fs.lstat("/proc/sys/../../etc/passwd"); err == nil {
		t.Fatal(".. out of the tree must fail")
	}
}

func TestProcSysFsMetadata(t *testing.T) {
	d, _ := fakeProcSys(t)
	fs := procSysFs{dir: int(d.Fd())}

	fi, err := fs.lstat("/proc/sys/net")
	if err != nil || !fi.FisDir || fi.Fname != "net" {
		t.Fatalf("lstat dir = %+v, %v", fi, err)
	}
	fi, err = fs.lstat("/proc/sys")
	if err != nil || !fi.FisDir || fi.Fname != "sys" {
		t.Fatalf("lstat root = %+v, %v", fi, err)
	}
	fi, err = fs.lstat("/proc/sys/link")
	if err != nil || fi.Fmode&os.ModeSymlink == 0 {
		t.Fatalf("lstat must not follow links: %+v, %v", fi, err)
	}
	ents, err := fs.readDir("/proc/sys/net/ipv4")
	if err != nil || len(ents) != 1 || ents[0].Fname != "ip_forward" || ents[0].Fsys == nil {
		t.Fatalf("readDir = %+v, %v", ents, err)
	}
	if l, err := fs.readLink("/proc/sys/link"); err != nil || l != "net/ipv4/ip_forward" {
		t.Fatalf("readLink = %q, %v", l, err)
	}
}

// open() checks permissions (no read/write follows: see processOpenFileRequest).
func TestProcSysFsOpen(t *testing.T) {
	d, _ := fakeProcSys(t)
	fs := procSysFs{dir: int(d.Fd())}

	if err := fs.open("/proc/sys/net/ipv4/ip_forward", unix.O_RDWR); err != nil {
		t.Fatalf("open rw = %v", err)
	}
	if os.Geteuid() != 0 { // root bypasses mode bits
		if err := fs.open("/proc/sys/kernel_ro", unix.O_WRONLY); !errors.Is(err, syscall.EACCES) {
			t.Fatalf("open ro file for write: want EACCES, got %v", err)
		}
	}
	// flags that would create/truncate are dropped, never applied
	if err := fs.open("/proc/sys/new", unix.O_WRONLY|unix.O_CREAT); err == nil {
		t.Fatal("O_CREAT must not create files")
	}
}

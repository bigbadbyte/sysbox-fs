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

// Agent side of /proc/sys passthrough for nested user namespaces (SBX-006;
// see handler/implementations/procSysNested.go): file operations relative to
// a /proc/sys dir fd opened by sysbox-fs, never escaping it.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"golang.org/x/sys/unix"
)

// Env var (and fd number) through which sysbox-fs hands the /proc/sys dir fd
// to the agent. fd 3 is the init pipe.
const (
	procSysFdEnv   = "_SYSBOXFS_PROCSYSFD"
	agentProcSysFd = 4
)

// Resolution for every path: beneath the dir fd, no magic links (/proc's
// fd/ and exe links), no crossing into other mounts.
const procSysResolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV

type procSysFs struct {
	dir int
}

// procSysRel maps an absolute /proc/sys path to one relative to the dir fd.
// Only canonical paths are accepted (no "..", "." or "//" components):
// sysbox-fs always sends them, so anything else is refused outright.
func procSysRel(p string) (string, error) {
	clean := path.Clean(p)
	if clean != strings.TrimSuffix(p, "/") {
		return "", fmt.Errorf("non-canonical path %q: %w", p, syscall.EINVAL)
	}
	if clean == "/proc/sys" {
		return ".", nil
	}
	if !strings.HasPrefix(clean, "/proc/sys/") {
		return "", fmt.Errorf("not a /proc/sys path %q: %w", p, syscall.EINVAL)
	}
	return strings.TrimPrefix(clean, "/proc/sys/"), nil
}

func (f procSysFs) openat(p string, flags uint64, resolve uint64) (*os.File, error) {
	rel, err := procSysRel(p)
	if err != nil {
		return nil, err
	}
	// never create or truncate anything
	flags &^= unix.O_CREAT | unix.O_TRUNC | unix.O_EXCL | unix.O_TMPFILE
	fd, err := unix.Openat2(f.dir, rel, &unix.OpenHow{
		Flags:   flags | unix.O_CLOEXEC,
		Resolve: resolve,
	})
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: p, Err: err}
	}
	return os.NewFile(uintptr(fd), p), nil
}

func (f procSysFs) open(p string, flags int) error {
	file, err := f.openat(p, uint64(flags), procSysResolve)
	if err != nil {
		return err
	}
	return file.Close()
}

func (f procSysFs) readAt(p string, off int64, n int) ([]byte, error) {
	file, err := f.openat(p, unix.O_RDONLY, procSysResolve)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	buf := make([]byte, n)
	sz, err := file.ReadAt(buf, off)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:sz], nil
}

func (f procSysFs) writeAt(p string, off int64, data []byte) error {
	file, err := f.openat(p, unix.O_WRONLY, procSysResolve)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteAt(data, off)
	return err
}

// lstat stats p itself (not a symlink's target).
func (f procSysFs) lstat(p string) (domain.FileInfo, error) {
	file, err := f.openat(p, unix.O_PATH|unix.O_NOFOLLOW, procSysResolve)
	if err != nil {
		return domain.FileInfo{}, err
	}
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstatat(int(file.Fd()), "", &st, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return domain.FileInfo{}, &os.PathError{Op: "lstat", Path: p, Err: err}
	}
	return fileInfo(path.Base(path.Clean(p)), &st), nil
}

func (f procSysFs) readDir(p string) ([]domain.FileInfo, error) {
	dir, err := f.openat(p, unix.O_RDONLY|unix.O_DIRECTORY, procSysResolve)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	var out []domain.FileInfo
	for _, name := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			continue // gone meanwhile
		}
		out = append(out, fileInfo(name, &st))
	}
	return out, nil
}

func (f procSysFs) readLink(p string) (string, error) {
	file, err := f.openat(p, unix.O_PATH|unix.O_NOFOLLOW, procSysResolve)
	if err != nil {
		return "", err
	}
	defer file.Close()
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(int(file.Fd()), "", buf)
	if err != nil {
		return "", &os.PathError{Op: "readlink", Path: p, Err: err}
	}
	return string(buf[:n]), nil
}

// fileInfo converts a stat result the way os.Lstat()'s FileInfo would be.
func fileInfo(name string, st *unix.Stat_t) domain.FileInfo {
	mode := os.FileMode(st.Mode & 0777)
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		mode |= os.ModeDir
	case unix.S_IFLNK:
		mode |= os.ModeSymlink
	}
	sys := &syscall.Stat_t{
		Dev: st.Dev, Ino: st.Ino, Nlink: st.Nlink, Mode: st.Mode,
		Uid: st.Uid, Gid: st.Gid, Rdev: st.Rdev, Size: st.Size,
		Blksize: st.Blksize, Blocks: st.Blocks,
		Atim: syscall.Timespec(st.Atim), Mtim: syscall.Timespec(st.Mtim),
		Ctim: syscall.Timespec(st.Ctim),
	}
	return domain.FileInfo{
		Fname:    name,
		Fsize:    st.Size,
		Fmode:    mode,
		FmodTime: time.Unix(st.Mtim.Sec, st.Mtim.Nsec),
		FisDir:   st.Mode&unix.S_IFMT == unix.S_IFDIR,
		Fsys:     sys,
	}
}

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

// Package nsutil has small helpers for identifying Linux namespaces of
// processes: their inodes and the user namespaces owning them.
package nsutil

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func nsPath(pid uint32, ns string) string {
	return fmt.Sprintf("/proc/%d/ns/%s", pid, ns)
}

// Inode returns the inode of namespace ns ("user", "pid", "net", ...) of
// process pid.
func Inode(pid uint32, ns string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(nsPath(pid, ns), &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

// OpenOwner returns an fd for the user ns owning namespace ns of process pid
// (NS_GET_USERNS). The caller closes it.
func OpenOwner(pid uint32, ns string) (*os.File, error) {
	f, err := os.Open(nsPath(pid, ns))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fd, err := unix.IoctlRetInt(int(f.Fd()), unix.NS_GET_USERNS)
	if err != nil {
		return nil, fmt.Errorf("NS_GET_USERNS on %s ns of pid %d: %w", ns, pid, err)
	}
	return os.NewFile(uintptr(fd), "userns"), nil
}

// OwnerInode returns the inode of the user ns owning namespace ns of process
// pid.
func OwnerInode(pid uint32, ns string) (uint64, error) {
	f, err := OpenOwner(pid, ns)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

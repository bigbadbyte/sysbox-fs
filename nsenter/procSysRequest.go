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

// Agent side of /proc/sys passthrough for nested user namespaces (SBX-006):
// when sysbox-fs handed us a /proc/sys dir fd, file requests are served
// relative to it (procSysFs) instead of a freshly mounted procfs.

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

// procSysFdFromEnv returns the /proc/sys dir fd handed to us (-1 if none).
func procSysFdFromEnv() (int, error) {
	v := os.Getenv(procSysFdEnv)
	if v == "" {
		return -1, nil
	}
	fd, err := strconv.Atoi(v)
	if err != nil {
		return -1, fmt.Errorf("Unable to convert %s=%s to int: %s", procSysFdEnv, v, err)
	}
	return fd, nil
}

// procSysErr makes an error response keeping err's errno (the kernel's
// verdict, e.g. EACCES from a sysctl permission check).
func procSysErr(err error) *domain.NSenterMessage {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		errno = syscall.EIO
	}
	return &domain.NSenterMessage{
		Type:    domain.ErrorResponse,
		Payload: &fuse.IOerror{RcvError: errno, Message: err.Error()},
	}
}

func procSysOK(t domain.NSenterMsgType, payload interface{}) *domain.NSenterMessage {
	return &domain.NSenterMessage{Type: t, Payload: payload}
}

// processProcSysRequest serves file requests through the /proc/sys fd and
// returns true, or returns false (no fd, or another request type) for the
// regular handlers to run.
func (e *NSenterEvent) processProcSysRequest() bool {
	if e.procSysFd < 0 {
		return false
	}
	fs := procSysFs{dir: e.procSysFd}

	switch p := e.ReqMsg.Payload.(type) {
	case domain.ReadFilePayload:
		data, err := fs.readAt(p.File, p.Offset, p.Len)
		e.ResMsg = procSysResult(err, domain.ReadFileResponse, data)
	case domain.WriteFilePayload:
		e.ResMsg = procSysResult(fs.writeAt(p.File, p.Offset, p.Data), domain.WriteFileResponse, nil)
	case domain.LookupPayload:
		fi, err := fs.lstat(p.Entry)
		e.ResMsg = procSysResult(err, domain.LookupResponse, fi)
	case domain.ReadDirPayload:
		ents, err := fs.readDir(p.Dir)
		e.ResMsg = procSysResult(err, domain.ReadDirResponse, ents)
	case domain.ReadLinkPayload:
		l, err := fs.readLink(p.Link)
		e.ResMsg = procSysResult(err, domain.ReadLinkResponse, l)
	case domain.OpenFilePayload:
		e.ResMsg = procSysOpen(fs, p)
	default:
		return false
	}
	return true
}

// viaProcSys serves the request through the /proc/sys fd if we have one, or
// runs the regular handler.
func (e *NSenterEvent) viaProcSys(regular func() error) error {
	if e.processProcSysRequest() {
		return nil
	}
	return regular()
}

func procSysResult(err error, t domain.NSenterMsgType, payload interface{}) *domain.NSenterMessage {
	if err != nil {
		return procSysErr(err)
	}
	return procSysOK(t, payload)
}

func procSysOpen(fs procSysFs, p domain.OpenFilePayload) *domain.NSenterMessage {
	flags, err := strconv.Atoi(p.Flags)
	if err != nil {
		return procSysErr(fmt.Errorf("bad open flags %q: %w", p.Flags, syscall.EINVAL))
	}
	return procSysResult(fs.open(p.File, flags), domain.OpenFileResponse, nil)
}

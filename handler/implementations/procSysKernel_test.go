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

package implementations_test

import (
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/handler/implementations"
	"github.com/nestybox/sysbox-fs/mocks"
	"github.com/nestybox/sysbox-fs/nsenter"
	"github.com/stretchr/testify/mock"
)

// /proc/sys/kernel/{hostname,domainname} are UTS-namespaced: they must be
// read in the requester's namespaces (passthrough), never from a cache
// filled from sysbox-fs' own (host) view (SBX-005).
func TestProcSysKernel_ReadHostnameUsesRequesterNamespaces(t *testing.T) {
	for _, resource := range []string{"hostname", "domainname"} {
		t.Run(resource, func(t *testing.T) {
			nss := &mocks.NSenterServiceIface{}
			hs := &mocks.HandlerServiceIface{}
			hs.On("NSenterService").Return(nss)
			hs.On("ProcessService").Return(prs)
			pt := &implementations.PassThrough{domain.HandlerBase{Name: "PassThrough", Service: hs}}
			hs.On("GetPassThroughHandler").Return(pt)

			h := &implementations.ProcSysKernel{implementations.ProcSysKernel_Handler.HandlerBase}
			h.HandlerBase.Service = hs

			cntr := css.ContainerCreate("uts-"+resource, uint32(1001), time.Time{},
				231072, 65535, 231072, 65535, nil, nil, nil)
			// a stale cached value must not be returned
			cntr.SetData("/proc/sys/kernel/"+resource, 0, []byte("host-name-leak\n"))

			n := ios.NewIOnode(resource, "/proc/sys/kernel/"+resource, 0)
			req := &domain.HandlerRequest{Pid: 1001, Container: cntr, Data: make([]byte, 64)}

			ev := &nsenter.NSenterEvent{}
			var gotNs *[]domain.NStype
			nss.On("NewEvent", uint32(1001), uint32(0), uint32(0), mock.Anything, mock.Anything,
				mock.MatchedBy(func(m *domain.NSenterMessage) bool {
					p, ok := m.Payload.(*domain.ReadFilePayload)
					return m.Type == domain.ReadFileRequest && ok && p.File == "/proc/sys/kernel/"+resource
				}), mock.Anything, false).
				Run(func(a mock.Arguments) { gotNs = a.Get(3).(*[]domain.NStype) }).
				Return(ev)
			nss.On("SendRequestEvent", ev).Return(nil)
			nss.On("ReceiveResponseEvent", ev).Return(&domain.NSenterMessage{
				Type:    domain.ReadFileResponse,
				Payload: []byte("cntr-name\n"),
			})

			sz, err := h.Read(n, req)
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if got := string(req.Data[:sz]); got != "cntr-name\n" {
				t.Fatalf("Read = %q, want the requester's value", got)
			}
			if gotNs == nil || !containsNs(*gotNs, domain.NStypeUts) {
				t.Fatalf("read must enter the requester's uts ns, got %v", gotNs)
			}
			if !req.NoCache {
				t.Fatal("UTS-namespaced values must not be cached per container")
			}
		})
	}
}

// Writes go to the requester's UTS ns via the agent (the kernel applies its
// own permission check there), not into a per-container cache.
func TestProcSysKernel_WriteHostnameUsesRequesterNamespaces(t *testing.T) {
	nss := &mocks.NSenterServiceIface{}
	hs := &mocks.HandlerServiceIface{}
	hs.On("NSenterService").Return(nss)
	hs.On("ProcessService").Return(prs)
	pt := &implementations.PassThrough{domain.HandlerBase{Name: "PassThrough", Service: hs}}
	hs.On("GetPassThroughHandler").Return(pt)

	h := &implementations.ProcSysKernel{implementations.ProcSysKernel_Handler.HandlerBase}
	h.HandlerBase.Service = hs

	cntr := css.ContainerCreate("uts-write", uint32(1001), time.Time{},
		231072, 65535, 231072, 65535, nil, nil, nil)
	n := ios.NewIOnode("hostname", "/proc/sys/kernel/hostname", 0)
	req := &domain.HandlerRequest{Pid: 1001, Container: cntr, Data: []byte("new\n")}

	ev := &nsenter.NSenterEvent{}
	var gotNs *[]domain.NStype
	nss.On("NewEvent", uint32(1001), uint32(0), uint32(0), mock.Anything, mock.Anything,
		mock.MatchedBy(func(m *domain.NSenterMessage) bool {
			p, ok := m.Payload.(*domain.WriteFilePayload)
			return m.Type == domain.WriteFileRequest && ok &&
				p.File == "/proc/sys/kernel/hostname" && string(p.Data) == "new\n"
		}), mock.Anything, false).
		Run(func(a mock.Arguments) { gotNs = a.Get(3).(*[]domain.NStype) }).
		Return(ev)
	nss.On("SendRequestEvent", ev).Return(nil)
	nss.On("ReceiveResponseEvent", ev).Return(&domain.NSenterMessage{
		Type: domain.WriteFileResponse, Payload: "",
	})

	if _, err := h.Write(n, req); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if gotNs == nil || !containsNs(*gotNs, domain.NStypeUts) {
		t.Fatalf("write must enter the requester's uts ns, got %v", gotNs)
	}
	var cached []byte
	if sz, _ := cntr.Data("/proc/sys/kernel/hostname", 0, &cached); sz != 0 {
		t.Fatalf("hostname must not be cached per container, got %q", cached)
	}
}

func containsNs(nss []domain.NStype, want domain.NStype) bool {
	for _, n := range nss {
		if n == want {
			return true
		}
	}
	return false
}

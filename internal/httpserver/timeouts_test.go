// Copyright (C) 2026 Chris Boot
// Copyright (C) 2026 Vox Pupuli and contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package httpserver_test

import (
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/httpserver"
)

var _ = Describe("New", func() {
	// Distinct values per field, so a timeout copied into the wrong slot fails
	// rather than coinciding.
	t := httpserver.Timeouts{
		ReadHeader: 1 * time.Second,
		Read:       2 * time.Second,
		Write:      3 * time.Second,
		Idle:       4 * time.Second,
	}

	DescribeTable("sets each timeout on the server",
		func(field func(*http.Server) time.Duration, want time.Duration) {
			Expect(field(httpserver.New("127.0.0.1:0", http.NotFoundHandler(), t))).To(Equal(want))
		},
		Entry("ReadHeaderTimeout", func(s *http.Server) time.Duration { return s.ReadHeaderTimeout }, 1*time.Second),
		Entry("ReadTimeout", func(s *http.Server) time.Duration { return s.ReadTimeout }, 2*time.Second),
		Entry("WriteTimeout", func(s *http.Server) time.Duration { return s.WriteTimeout }, 3*time.Second),
		Entry("IdleTimeout", func(s *http.Server) time.Duration { return s.IdleTimeout }, 4*time.Second),
	)

	It("serves the given handler on the given address", func() {
		handler := http.NewServeMux()
		srv := httpserver.New("127.0.0.1:0", handler, t)
		Expect(srv.Addr).To(Equal("127.0.0.1:0"))
		Expect(srv.Handler).To(BeIdenticalTo(handler))
	})
})

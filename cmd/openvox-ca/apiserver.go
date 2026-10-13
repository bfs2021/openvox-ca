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

package main

import (
	"net/http"

	"github.com/voxpupuli/openvox-ca/internal/httpserver"
)

// newAPIServer builds the http.Server for the Puppet CA API on addr. It lives
// outside newRootCmd so a spec can hold its timeouts against the metrics
// listener's: the two share httpserver.Defaults and must not drift apart.
func newAPIServer(addr string, handler http.Handler) *http.Server {
	srv := httpserver.New(addr, handler, httpserver.Defaults())
	srv.MaxHeaderBytes = 1 << 20
	return srv
}

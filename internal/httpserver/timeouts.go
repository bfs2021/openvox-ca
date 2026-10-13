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

// Package httpserver holds the connection timeouts shared by the CA's HTTP
// listeners: the Puppet CA API and the Prometheus metrics exporter. Defining
// them once means a change to one listener's budget cannot silently leave the
// other behind.
package httpserver

import (
	"net/http"
	"time"
)

// Timeouts bounds each phase of a connection to an http.Server. Without them,
// a client that sends its headers and then trickles the body, or never reads
// the response, holds a connection and its goroutine open indefinitely.
type Timeouts struct {
	// ReadHeader bounds reading the request line and headers.
	ReadHeader time.Duration
	// Read bounds reading the whole request, headers and body together.
	Read time.Duration
	// Write runs from the end of the request headers to the last byte of the
	// response, so it covers the handler producing the response as well as
	// sending it.
	Write time.Duration
	// Idle bounds how long a keep-alive connection waits for its next request.
	Idle time.Duration
}

// Defaults returns the timeouts both of the CA's listeners use. It returns a
// value rather than exposing a package variable, so no caller can change them
// for the other listener.
//
// Write must outlast a metrics scrape, which gathers under its own budget
// before it writes a byte: see metrics.Exporter.NewServer before lowering it.
// docs/api.md also cites the API's 60s write budget against ca.LockTimeout,
// so a change to Write owes that page an update.
func Defaults() Timeouts {
	return Timeouts{
		ReadHeader: 10 * time.Second,
		Read:       30 * time.Second,
		Write:      60 * time.Second,
		Idle:       120 * time.Second,
	}
}

// New builds an *http.Server for handler on addr, bounded by t. A zero field
// in t leaves that phase unbounded, so production callers pass Defaults.
//
// The server is built here, rather than t being copied onto one the caller
// built, because gosec's slowloris check (G112) reads only the struct literal.
// It checks that ReadHeaderTimeout is named, not what value it is given, so
// it is satisfied here for good and says nothing about what New's callers
// pass. The specs on each listener pin the values instead.
func New(addr string, handler http.Handler, t Timeouts) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: t.ReadHeader,
		ReadTimeout:       t.Read,
		WriteTimeout:      t.Write,
		IdleTimeout:       t.Idle,
	}
}

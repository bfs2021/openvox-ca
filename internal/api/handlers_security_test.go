// Copyright (C) 2026 Trevor Vaughan
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

package api_test

import (
	"bytes"
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// csrFaultBackend fails Exists or Put on one key with a fixed error, standing
// in for a backend that is reachable but refusing that operation.
type csrFaultBackend struct {
	storage.Backend
	key        string
	err        error
	failExists bool
	failPut    bool
}

func (b *csrFaultBackend) Exists(ctx context.Context, key string) (bool, error) {
	if b.failExists && key == b.key {
		return false, b.err
	}
	return b.Backend.Exists(ctx, key)
}

func (b *csrFaultBackend) Put(ctx context.Context, key string, data []byte, kind storage.BlobKind) error {
	if b.failPut && key == b.key {
		return b.err
	}
	return b.Backend.Put(ctx, key, data, kind)
}

var _ = Describe("API security hardening", func() {
	Context("internal errors are not leaked to clients", func() {
		It("returns a generic 500 body that does not contain the on-disk path when storage listing fails", func() {
			// Build a CA whose signed-cert listing is guaranteed to fail with a
			// path-bearing error: the "signed" entry is a regular file, so
			// os.ReadDir returns a *PathError containing the temp directory path.
			tmpDir, err := os.MkdirTemp("", "openvox-ca-leak-test")
			Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(tmpDir)

			Expect(os.MkdirAll(filepath.Join(tmpDir, "requests"), 0o755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(tmpDir, "signed"), []byte("not a directory"), 0o644)).To(Succeed())

			store := storage.New(tmpDir)
			leakCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			leakServer := api.New(leakCA)
			leakMux := leakServer.Routes()

			req := httptest.NewRequest("GET", "/certificate_statuses/any", nil)
			rr := httptest.NewRecorder()
			leakMux.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusInternalServerError))
			// The raw error chain (including the temp directory path) must not
			// reach the client.
			Expect(rr.Body.String()).NotTo(ContainSubstring(tmpDir))
			Expect(rr.Body.String()).NotTo(ContainSubstring("not a directory"))
			Expect(rr.Body.String()).To(ContainSubstring("internal server error"))
		})

		// Unauthenticated endpoint. Each entry faults one storage call on the
		// CSR's key with a path-bearing error, so the spec fails if either the
		// path or the error reaches the client. The duplicate check's lookup
		// is a separate entry because it runs first: a fault there must be a
		// 500 like any other, never the 400 that tells an agent to keep
		// waiting for a certificate nobody decided about.
		DescribeTable("returns a generic 500 on PUT /certificate_request when storage fails, without leaking the on-disk path",
			func(failExists bool) {
				tmpDir := GinkgoT().TempDir()
				const subject = "leaknode.test"
				fault := &fs.PathError{Op: "open", Path: filepath.Join(tmpDir, "requests", subject+".pem"), Err: syscall.EIO}

				backend := &csrFaultBackend{Backend: storage.NewFilesystemBackend(tmpDir), key: storage.CSRKey(subject), err: fault}
				if failExists {
					backend.failExists = true
				} else {
					backend.failPut = true
				}
				store := storage.NewWithBackend(backend, filepath.Join(tmpDir, "private"))
				Expect(store.EnsureDirs(context.Background())).To(Succeed())
				leakCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
				leakMux := api.New(leakCA).Routes()

				csrPEM, err := testutil.GenerateCSR(subject)
				Expect(err).NotTo(HaveOccurred())

				req := httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM))
				rr := httptest.NewRecorder()
				leakMux.ServeHTTP(rr, req)

				Expect(rr.Code).To(Equal(http.StatusInternalServerError))
				Expect(rr.Body.String()).To(ContainSubstring("internal server error"))
				// The storage path must never reach this unauthenticated client.
				Expect(rr.Body.String()).NotTo(ContainSubstring(tmpDir))
				Expect(rr.Body.String()).NotTo(ContainSubstring("requests"))
				Expect(rr.Body.String()).NotTo(ContainSubstring("input/output error"))
			},
			Entry("when saving the CSR fails", false),
			Entry("when the duplicate check cannot tell whether a CSR is pending", true),
		)
	})

	Context("JSON request bodies are size-capped", func() {
		var leakMux http.Handler

		BeforeEach(func() {
			tmpDir, err := os.MkdirTemp("", "openvox-ca-bodycap-test")
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { os.RemoveAll(tmpDir) })

			store := storage.New(tmpDir)
			Expect(store.EnsureDirs(context.Background())).To(Succeed())
			capCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			leakMux = api.New(capCA).Routes()
		})

		It("rejects an oversize POST /sign body with 413", func() {
			// A syntactically valid JSON body that exceeds the 1 MiB cap, so the
			// decoder keeps reading until MaxBytesReader trips (rather than
			// failing early on a malformed token).
			huge := bytes.Repeat([]byte("a"), (1<<20)+16)
			oversize := append(append([]byte(`{"certnames":["`), huge...), []byte(`"]}`)...)
			req := httptest.NewRequest("POST", "/sign", bytes.NewReader(oversize))
			rr := httptest.NewRecorder()
			leakMux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusRequestEntityTooLarge))
		})

		It("rejects an oversize PUT /clean body with 413", func() {
			// A syntactically valid JSON body that exceeds the 1 MiB cap, so the
			// decoder keeps reading until MaxBytesReader trips (rather than
			// failing early on a malformed token).
			huge := bytes.Repeat([]byte("a"), (1<<20)+16)
			oversize := append(append([]byte(`{"certnames":["`), huge...), []byte(`"]}`)...)
			req := httptest.NewRequest("PUT", "/clean", bytes.NewReader(oversize))
			rr := httptest.NewRecorder()
			leakMux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusRequestEntityTooLarge))
		})
	})
})

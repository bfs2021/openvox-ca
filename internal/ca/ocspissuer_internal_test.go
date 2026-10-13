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

package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/ocsp"

	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// White-box, because both properties sit below anything a request can reach
// today: ocsp.ParseRequest refuses every hash it cannot compute before the
// issuer check runs, and the lock is not observable from outside.
var _ = Describe("OCSP issuer check internals", func() {
	var issuer *x509.Certificate

	BeforeEach(func() {
		_, crtPEM, _, err := testutil.GenerateTestCAECDSA()
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(crtPEM)
		Expect(block).NotTo(BeNil())
		issuer, err = x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
	})

	// The guard keeps a hash x/crypto might one day accept, but this binary
	// cannot compute, from panicking on an unauthenticated endpoint.
	It("refuses a hash it cannot compute as malformed, without panicking", func() {
		req := &ocsp.Request{HashAlgorithm: crypto.Hash(0)}

		var err error
		Expect(func() { err = checkOCSPIssuer(req, issuer) }).NotTo(Panic())
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, ErrNotAuthoritative)).To(BeFalse())
		Expect(errors.Is(err, ErrInternal)).To(BeFalse())
	})

	// The guard exists for the day x/crypto accepts another hash: an answer
	// cached under a hash evictOCSPLocked does not walk would outlive a
	// revocation. So it must refuse a hash outside the list.
	It("refuses to cache a hash outside the list eviction walks", func() {
		Expect(ocspCacheableHash(crypto.SHA3_256)).To(BeFalse())
		Expect(ocspCacheableHash(crypto.MD5)).To(BeFalse())
	})

	// The other half of that contract: every hash the guard admits is one
	// eviction drops. Seeded directly, because no request can reach a hash
	// the guard would refuse.
	It("evicts an entry under every hash the guard admits", func() {
		c := New(nil, AutosignConfig{Mode: "off"}, "puppet.test")
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512, crypto.SHA512_256, crypto.SHA3_256, crypto.MD5} {
			if ocspCacheableHash(h) {
				c.ocspCache[ocspCacheKey{serial: "AA", hash: h}] = ocspCacheEntry{der: []byte("pre-signed good")}
			}
		}
		Expect(c.ocspCache).NotTo(BeEmpty())

		c.evictOCSPLocked("AA")

		Expect(c.ocspCache).To(BeEmpty(), "an admitted hash eviction does not walk would survive a revocation")
	})

	// CACert has already been parsed, so its SubjectPublicKeyInfo cannot fail
	// to unmarshal in practice. If it ever does, that is a fault of this CA's
	// own state, not of the request, and must not be reported as unauthorized.
	It("reports an unreadable CA public key as an internal error", func() {
		broken := *issuer
		broken.RawSubjectPublicKeyInfo = []byte("not DER")
		req := &ocsp.Request{HashAlgorithm: crypto.SHA256}

		err := checkOCSPIssuer(req, &broken)
		Expect(errors.Is(err, ErrInternal)).To(BeTrue(), "got %v", err)
		Expect(errors.Is(err, ErrNotAuthoritative)).To(BeFalse())
	})

	// The check hashes with whatever algorithm the caller chose, under c.mu.
	// A panic there must not leave the lock held. A CA with no certificate
	// makes the check panic without touching any process-global state.
	It("releases c.mu when the check panics", func() {
		c := New(nil, AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(c.CACert).To(BeNil())
		reqDER, err := testutil.BuildOCSPRequest(issuer, issuer)
		Expect(err).NotTo(HaveOccurred())

		Expect(func() { _, _ = c.AnswerOCSP(context.Background(), reqDER) }).To(Panic())

		Expect(c.mu.TryLock()).To(BeTrue(), "c.mu must not be left read-held")
		c.mu.Unlock()
	})
})

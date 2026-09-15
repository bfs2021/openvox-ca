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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// The startup decision on key-material permissions, and the reporting that
// follows it. World access is refused, because a CA private key every local
// account can read is one to treat as exposed. Group access never refuses: it is
// the mode the store is created with, so a correct deployment has it. A path
// whose permissions could not be read refuses on its own terms, since "chmod
// o-rwx" would be a remedy for a condition nobody established.
//
// The two halves are separate functions because they run at different points:
// the refusal happens in the parent before any logger exists, and the reporting
// once one does, so that it reaches a configured logfile.
var _ = Describe("key-material permissions at startup", func() {
	// captureAt installs a handler at the given level and returns what was
	// written, the idiom this package already uses for log assertions.
	captureAt := func(level slog.Level) *bytes.Buffer {
		GinkgoHelper()
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: level})))
		DeferCleanup(func() { slog.SetDefault(orig) })
		return &buf
	}
	captureWarnings := func() *bytes.Buffer { GinkgoHelper(); return captureAt(slog.LevelWarn) }
	captureAll := func() *bytes.Buffer { GinkgoHelper(); return captureAt(slog.LevelInfo) }

	// Distinct paths, and the realistic pairing: SQLite keeps the key across a
	// database and its sidecars, each with its own mode. Sharing one path between
	// the fixtures would make it impossible for any assertion here to catch the
	// refusal naming the wrong file.
	worldReadable := storage.KeyPermWarning{Path: "/var/lib/puppet-ca/ca.db-wal", Mode: os.FileMode(0o644)}
	// Deliberately not a prefix of the world-accessible path: "ca.db" is a
	// substring of "ca.db-wal", so a NotTo(ContainSubstring) over the pair could
	// never pass and the spec below would be unfailable in the wrong direction.
	groupReadable := storage.KeyPermWarning{Path: "/var/lib/puppet-ca/private/ca_key.pem", Mode: os.FileMode(0o640)}

	It("starts with nothing to report", func() {
		buf := captureAll()

		Expect(refuseOnKeyPermissions(nil, false)).To(Succeed(), "no findings")
		logKeyPermissions(nil, false)
		Expect(buf.String()).To(BeEmpty(), "nothing logged")
	})

	It("refuses to start on world-accessible key material", func() {
		err := refuseOnKeyPermissions([]storage.KeyPermWarning{worldReadable}, false)

		Expect(err).To(HaveOccurred(), "world-accessible key material")
		Expect(err.Error()).To(ContainSubstring("refusing to start"), "the refusal")
		Expect(err.Error()).To(ContainSubstring(worldReadable.Path), "the file at fault")
		Expect(err.Error()).To(ContainSubstring(worldReadable.Mode.String()), "the mode that made it a finding")
		Expect(err.Error()).To(ContainSubstring("chmod o-rwx"), "the remedy")
		Expect(err.Error()).To(ContainSubstring("rotated"), "what to do about a key that was exposed")
	})

	// Group access must not be a refusal. Under the chart's default fsGroup the
	// kubelet ORs group access back into the volume at every mount, so refusing
	// would stop the CA starting on the project's own recommended deployment.
	It("starts when key material is only group-accessible", func() {
		buf := captureWarnings()

		Expect(refuseOnKeyPermissions([]storage.KeyPermWarning{groupReadable}, false)).To(Succeed(),
			"group access must not stop the CA starting")
		Expect(buf.String()).To(BeEmpty(), "group access is not a warning-level condition")
	})

	// The group report itself, at Info. Asserted against a handler that admits
	// Info: a Warn-level buffer is empty on this path by construction, so a
	// NotTo(ContainSubstring) over it could never fail and the report could be
	// deleted with nothing noticing.
	It("reports group access once, at Info, naming the files", func() {
		buf := captureAll()

		logKeyPermissions([]storage.KeyPermWarning{groupReadable}, false)

		Expect(buf.String()).To(ContainSubstring("accessible to its group"), "the report")
		Expect(buf.String()).To(ContainSubstring(groupReadable.Path), "the file named")
		Expect(buf.String()).To(ContainSubstring(groupReadable.Mode.String()), "the mode")
		Expect(buf.String()).To(ContainSubstring("level=INFO"), "at Info, not Warn")
	})

	// The opt-out downgrades the refusal, and shouts. An operator who reaches for
	// it should be in no doubt what they have turned off.
	It("starts on world-accessible key material when told to, shouting about it", func() {
		buf := captureWarnings()

		Expect(refuseOnKeyPermissions([]storage.KeyPermWarning{worldReadable}, true)).To(Succeed(),
			"the opt-out downgrades the refusal")

		logKeyPermissions([]storage.KeyPermWarning{worldReadable}, true)
		Expect(buf.String()).To(ContainSubstring("INSECURE"), "the shouting")
		Expect(buf.String()).To(ContainSubstring("EVERY LOCAL ACCOUNT CAN READ THESE FILES"), "the shouting")
		Expect(buf.String()).To(ContainSubstring("ROTATE IT"), "what the operator must now do")
		Expect(buf.String()).To(ContainSubstring(worldReadable.Path), "the file named")
	})

	// A path whose permissions could not be read is refused too, and separately:
	// "world-accessible, chmod o-rwx" would be a false statement and a remedy
	// that cannot clear it. The opt-out deliberately does not cover it -- nobody
	// can have weighed a risk whose mode is unknown.
	Describe("a path whose permissions cannot be read", func() {
		unreadable := storage.KeyPermWarning{
			Path:       "/var/lib/puppet-ca/private",
			Unreadable: true,
			Err:        errors.New("permission denied"),
		}

		It("refuses, naming the path and the real error", func() {
			err := refuseOnKeyPermissions([]storage.KeyPermWarning{unreadable}, false)

			Expect(err).To(HaveOccurred(), "an unjudgeable path")
			Expect(err.Error()).To(ContainSubstring("could not be read"), "the real condition")
			Expect(err.Error()).To(ContainSubstring(unreadable.Path), "the path")
			Expect(err.Error()).To(ContainSubstring("permission denied"), "the underlying error")
			Expect(err.Error()).NotTo(ContainSubstring("chmod o-rwx"), "a remedy that could not clear it")
			Expect(err.Error()).NotTo(ContainSubstring("world-accessible"), "a mode nobody established")
		})

		It("refuses even under the opt-out", func() {
			err := refuseOnKeyPermissions([]storage.KeyPermWarning{unreadable}, true)

			Expect(err).To(HaveOccurred(), "the opt-out is about world access, not about not knowing")
		})
	})

	// The opt-out is for world access only; it does not silence anything else,
	// and it does not turn a group finding into a scream.
	It("does not scream about group access under the opt-out", func() {
		buf := captureAll()

		Expect(refuseOnKeyPermissions([]storage.KeyPermWarning{groupReadable}, true)).To(Succeed())
		logKeyPermissions([]storage.KeyPermWarning{groupReadable}, true)

		Expect(buf.String()).To(ContainSubstring("accessible to its group"), "still reported")
		Expect(buf.String()).NotTo(ContainSubstring("INSECURE"), "no scream for group access")
	})

	// Several findings, and the refusal has to fire on the world one wherever it
	// sits in the list rather than only when it happens to come first.
	It("refuses when a world-accessible file follows a group-accessible one", func() {
		_ = captureWarnings()

		err := refuseOnKeyPermissions([]storage.KeyPermWarning{groupReadable, worldReadable}, false)

		Expect(err).To(HaveOccurred(), "the world-accessible file is not first")
		Expect(err.Error()).To(ContainSubstring("refusing to start"), "the refusal")
		Expect(err.Error()).To(ContainSubstring(worldReadable.Path), "names the world-accessible file")
		Expect(err.Error()).NotTo(ContainSubstring(groupReadable.Path),
			"does not send the operator to chmod a file that is merely group-accessible")
	})

	// Every world-accessible path, not just the first. SQLite keeps the key in
	// four files whose modes move together, so naming one would have the operator
	// fix it, restart, and be refused again by the next.
	It("names every world-accessible file in one refusal", func() {
		second := storage.KeyPermWarning{Path: "/var/lib/puppet-ca/ca.db-shm", Mode: os.FileMode(0o644)}

		err := refuseOnKeyPermissions([]storage.KeyPermWarning{worldReadable, second}, false)

		Expect(err).To(HaveOccurred(), "two world-accessible files")
		Expect(err.Error()).To(ContainSubstring(worldReadable.Path), "the first")
		Expect(err.Error()).To(ContainSubstring(second.Path), "the second")
	})
})

// The startup path itself, through the command an operator actually runs. The
// specs above drive the decision as a function; these drive the wiring -- that
// it is called at all, that it is called before anything forks or writes a key,
// and that the config field reaches it. Each of those is a mutation the
// function-level specs cannot see.
var _ = Describe("the server's own startup, on key-material permissions", func() {
	// worldReadableCADir bootstraps a CA and then widens its private key, which
	// is the condition the check exists to refuse.
	worldReadableCADir := func() string {
		GinkgoHelper()
		caDir := GinkgoT().TempDir()
		bootstrapCAInDir(caDir, "puppet.example.com")
		keyPath := filepath.Join(caDir, "private", "ca_key.pem")
		Expect(keyPath).To(BeAnExistingFile(), "the bootstrapped CA key")
		Expect(os.Chmod(keyPath, 0o644)).To(Succeed(), "make it world-readable")
		return caDir
	}

	It("refuses to start, through the command an operator actually runs", func() {
		caDir := worldReadableCADir()

		cmd := newRootCmd()
		cmd.SetOut(GinkgoWriter)
		cmd.SetErr(GinkgoWriter)
		cmd.SetArgs([]string{"--cadir", caDir, "--host", "127.0.0.1", "--port", "0"})

		// Bounded, for the same reason the instance-lock spec is: if the check
		// regressed, the next thing this command does is fork the launcher and
		// supervise it for ever. A spec that hangs on regression is worse than
		// one that fails.
		done := make(chan error, 1)
		go func() { done <- cmd.Execute() }()

		var err error
		Eventually(done, "30s").Should(Receive(&err),
			"the refusal must come before the launcher forks; a hang here means it does not")
		Expect(err).To(MatchError(ContainSubstring("refusing to start")),
			"world-readable key material must be refused at the top level")
		Expect(err).To(MatchError(ContainSubstring("chmod o-rwx")), "the remedy")
	})

	It("refuses under --daemon instead of reporting success", func() {
		// --daemon discards the child's stdout and stderr, so a refusal raised
		// past the fork reaches nobody: the operator is told the CA started, gets
		// exit 0, and the child dies in silence.
		caDir := worldReadableCADir()

		cmd := newRootCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(GinkgoWriter)
		cmd.SetArgs([]string{"--cadir", caDir, "--host", "127.0.0.1", "--port", "0", "--daemon"})

		err := cmd.Execute()
		Expect(err).To(MatchError(ContainSubstring("refusing to start")))
		Expect(out.String()).NotTo(ContainSubstring("started in background"),
			"reporting a background start for a process that was refused is the failure")
	})

	// What connects cfg.InsecureAllowWorldReadableKeys to the decision. Driven
	// through preflightKeyPermissions rather than the whole command, because the
	// opt-out's success path starts a server: under --daemon the binary re-execs
	// itself, which in a test is the test binary, and without it the command
	// serves until killed. Neither belongs in a suite. The two specs above
	// already pin that the check runs at all and runs before the fork; this pins
	// that the config field reaches it.
	It("lets the opt-out through to the decision", func() {
		caDir := worldReadableCADir()
		cfg := &serverConfig{CADir: caDir}

		_, err := preflightKeyPermissions(context.Background(), cfg)
		Expect(err).To(MatchError(ContainSubstring("refusing to start")),
			"without the opt-out, world-readable key material is refused")

		cfg.InsecureAllowWorldReadableKeys = true
		warnings, err := preflightKeyPermissions(context.Background(), cfg)
		Expect(err).NotTo(HaveOccurred(), "the opt-out must reach the decision")
		Expect(warnings).NotTo(BeEmpty(), "the findings still come back, to be logged")
	})
})

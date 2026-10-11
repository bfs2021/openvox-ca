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

package ca

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

// Encrypted PEM envelope format (inside the PEM block body):
//
//	version    1 byte   (currently 0x01)
//	salt      32 bytes  (random, for Argon2id)
//	nonce     12 bytes  (random, for AES-256-GCM)
//	ciphertext variable (AES-256-GCM encrypted PKCS#8 DER + 16-byte GCM tag)
//
// Key derivation: Argon2id(passphrase, salt, time=3, memory=64 MiB, threads=4) → 32 bytes.
// Plaintext: PKCS#8 DER encoding of the private key.

const (
	keyEncVersion  = 0x01
	keyEncSaltLen  = 32
	keyEncNonceLen = 12
	keyEncMinLen   = 1 + keyEncSaltLen + keyEncNonceLen + aes.BlockSize // version + salt + nonce + min ciphertext

	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MiB
	argon2Threads = 4
	argon2KeyLen  = 32

	encryptedPEMType = "ENCRYPTED PRIVATE KEY"
)

// KeyPassphraseConfig holds the passphrase source for CA key encryption.
type KeyPassphraseConfig struct {
	// PassphraseFile is a path to a file containing the passphrase (first line, trimmed).
	PassphraseFile string
	// PassphraseEnvVar is the name of the environment variable holding the passphrase.
	// Defaults to DefaultPassphraseEnvVar.
	PassphraseEnvVar string
}

// DefaultPassphraseEnvVar is the variable the passphrase is read from when
// KeyPassphraseConfig.PassphraseEnvVar is empty.
const DefaultPassphraseEnvVar = "PUPPET_CA_KEY_PASSPHRASE" //nolint:gosec // G101: the name of the variable holding the passphrase, not a passphrase

// EnvVar returns the name of the environment variable the passphrase is read
// from.
//
// Exported so the launcher withholds from the frontend exactly the variable
// this package reads, rather than its own copy of the name.
func (cfg KeyPassphraseConfig) EnvVar() string {
	if cfg.PassphraseEnvVar != "" {
		return cfg.PassphraseEnvVar
	}
	return DefaultPassphraseEnvVar
}

// deriveKey derives a 32-byte AES key from passphrase and salt using Argon2id.
func deriveKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
}

// encryptKeyPEM encrypts a private key (as PKCS#8 DER) with the given
// passphrase and returns PEM-encoded encrypted data.
func encryptKeyPEM(pkcs8DER, passphrase []byte) ([]byte, error) {
	salt := make([]byte, keyEncSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	key := deriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, pkcs8DER, nil)

	// Assemble envelope: version || salt || nonce || ciphertext.
	envelope := make([]byte, 0, 1+len(salt)+len(nonce)+len(ciphertext))
	envelope = append(envelope, keyEncVersion)
	envelope = append(envelope, salt...)
	envelope = append(envelope, nonce...)
	envelope = append(envelope, ciphertext...)

	return pem.EncodeToMemory(&pem.Block{
		Type:  encryptedPEMType,
		Bytes: envelope,
	}), nil
}

// decryptKeyDER decrypts an encrypted PEM envelope and returns the PKCS#8 DER.
func decryptKeyDER(envelope, passphrase []byte) ([]byte, error) {
	if len(envelope) < keyEncMinLen {
		return nil, fmt.Errorf("encrypted key envelope too short")
	}
	if envelope[0] != keyEncVersion {
		return nil, fmt.Errorf("unsupported encrypted key version: %d", envelope[0])
	}

	offset := 1
	salt := envelope[offset : offset+keyEncSaltLen]
	offset += keyEncSaltLen
	nonce := envelope[offset : offset+keyEncNonceLen]
	offset += keyEncNonceLen
	ciphertext := envelope[offset:]

	key := deriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong passphrase?): %w", err)
	}
	return plaintext, nil
}

// isEncryptedPEM reports whether the PEM block is an encrypted private key.
func isEncryptedPEM(block *pem.Block) bool {
	return block != nil && block.Type == encryptedPEMType
}

// encryptAndMarshalKey encrypts a crypto.Signer private key with the given
// passphrase and returns PEM-encoded encrypted data.
func encryptAndMarshalKey(key any, passphrase []byte) ([]byte, error) {
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshalling key to PKCS#8: %w", err)
	}
	return encryptKeyPEM(pkcs8DER, passphrase)
}

// resolvePassphrase determines the CA key passphrase from the configured
// sources: PassphraseFile, then the environment variable. There is no third
// source -- with neither configured, this refuses.
//
// It used to generate one and write it to <cadir>/private/.ca_key_passphrase,
// beside the key it protects. docs/ca-key-security.md offers encryption at rest
// as protection against a copied backup, disk image or snapshot, and that claim
// is simply false when the passphrase travels in the same directory as the
// ciphertext: anybody holding the copy holds both halves. The default was the
// configuration that made the documented guarantee untrue, and nothing told the
// operator (#432).
//
// Refusing also fixes a second defect of the same code. The load path calls
// this too, so an operator whose passphrase came from the environment and who
// restarted without it set did not get an error about the missing passphrase --
// they got a *freshly generated* one, written over nothing, and then a failure
// to decrypt the existing key with it. A missing passphrase is now a missing
// passphrase wherever it is noticed.
//
// The error names the remedy, including for a store that already has a
// generated passphrase: that file is still a perfectly good passphrase, and
// pointing ca_key_passphrase_file at it keeps the CA working.
func resolvePassphrase(cfg KeyPassphraseConfig, caDir string) ([]byte, error) {
	envVar := cfg.EnvVar()

	// 1. Explicit file.
	if cfg.PassphraseFile != "" {
		pp, err := readPassphraseFile(cfg.PassphraseFile)
		if err != nil {
			return nil, fmt.Errorf("reading --ca-key-passphrase-file %s: %w", cfg.PassphraseFile, err)
		}
		return pp, nil
	}

	// 2. Environment variable.
	if val := os.Getenv(envVar); val != "" {
		return []byte(val), nil
	}

	// 3. Nothing configured. An earlier version would have generated one here.
	autoPath := autoPassphrasePath(caDir)
	if _, err := os.Stat(autoPath); err == nil {
		return nil, fmt.Errorf("encrypt_ca_key is set and no passphrase source is configured, "+
			"but an earlier version generated one at %s -- openvox-ca no longer generates or reads "+
			"it implicitly, because a passphrase stored beside the key it protects defends neither "+
			"against a copied cadir; set ca_key_passphrase_file to that path to keep using it, or "+
			"set %s, then move the file somewhere the cadir's backups do not reach",
			autoPath, envVar)
	}
	return nil, fmt.Errorf("encrypt_ca_key is set but no passphrase source is configured; "+
		"set ca_key_passphrase_file to a file holding the passphrase, or set %s. openvox-ca does "+
		"not generate one: it would have to live beside the key it protects, which defends neither "+
		"against a copied backup, disk image or snapshot", envVar)
}

// readPassphraseFile reads a passphrase from a file (first line, whitespace-trimmed).
func readPassphraseFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Use first line only, trim whitespace.
	for i, b := range data {
		if b == '\n' || b == '\r' {
			data = data[:i]
			break
		}
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("passphrase file %s is empty", path)
	}
	return data, nil
}

// autoPassphrasePath returns the path to the auto-generated passphrase file.
func autoPassphrasePath(caDir string) string {
	return filepath.Join(caDir, "private", ".ca_key_passphrase")
}

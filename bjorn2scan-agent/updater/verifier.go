package updater

import (
	"bytes"
	"fmt"
	"os"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// Verifier handles signature verification using sigstore-go keyless verification.
type Verifier struct {
	identityRegexp string
	oidcIssuer     string
}

// NewVerifier creates a new signature verifier.
func NewVerifier(identityRegexp, oidcIssuer string) *Verifier {
	return &Verifier{
		identityRegexp: identityRegexp,
		oidcIssuer:     oidcIssuer,
	}
}

// VerifySignature verifies the Sigstore bundle for blobPath.
//
//   - blobPath:   the file whose integrity is being verified (the .tar.gz tarball).
//   - bundlePath: the .sigstore JSON bundle produced by cosign sign-blob --bundle.
//
// Verification checks:
//  1. The bundle's Rekor transparency-log entry is valid (threshold: 1)
//  2. The signing certificate was issued to v.oidcIssuer with SAN matching v.identityRegexp
//  3. The bundle's artifact digest matches the content of blobPath
func (v *Verifier) VerifySignature(blobPath, bundlePath string) error {
	// Load the Sigstore bundle (.sigstore JSON)
	b, err := bundle.LoadJSONFromPath(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to load signature bundle: %w", err)
	}

	// Fetch the Sigstore public-good trust root from TUF (tuf.sigstore.dev).
	// Network access is required here; the agent is downloading an update anyway.
	// DisableLocalCache avoids writing to $HOME/.sigstore, which may not be writable
	// when the agent runs as a systemd service with a read-only filesystem.
	trustedRoot, err := root.FetchTrustedRootWithOptions(tuf.DefaultOptions().WithDisableLocalCache())
	if err != nil {
		return fmt.Errorf("failed to fetch trusted root: %w", err)
	}

	// Require at least one transparency-log entry and one observer timestamp.
	verifier, err := verify.NewVerifier(trustedRoot,
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	// Read the blob content so the verifier can check the artifact digest.
	blobBytes, err := os.ReadFile(blobPath)
	if err != nil {
		return fmt.Errorf("failed to read blob %s: %w", blobPath, err)
	}

	// Build the certificate identity policy:
	//   issuer    = e.g. "https://token.actions.githubusercontent.com"
	//   sanRegexp = e.g. "https://github.com/bvboe/b2s-go/*"
	certID, err := verify.NewShortCertificateIdentity(v.oidcIssuer, "", "", v.identityRegexp)
	if err != nil {
		return fmt.Errorf("invalid certificate identity: %w", err)
	}

	policy := verify.NewPolicy(
		verify.WithArtifact(bytes.NewReader(blobBytes)),
		verify.WithCertificateIdentity(certID),
	)

	if _, err := verifier.Verify(b, policy); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

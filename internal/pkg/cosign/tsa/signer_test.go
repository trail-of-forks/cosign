// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tsa

import (
	"bytes"
	"context"
	"crypto"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/cosign/v2/internal/pkg/cosign/payload"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa/mock"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/signature"
)

func mustGetNewSigner(t *testing.T) signature.Signer {
	t.Helper()
	priv, err := cosign.GeneratePrivateKey(v1.SupportedAlgorithm_ECDSA_SHA2_256_NISTP256)
	if err != nil {
		t.Fatalf("cosign.GeneratePrivateKey() failed: %v", err)
	}
	s, err := signature.LoadSignerVerifier(priv, crypto.SHA256, signature.LoadDefaultSV, nil)
	if err != nil {
		t.Fatalf("signature.LoadECDSASignerVerifier(key, crypto.SHA256) failed: %v", err)
	}
	return s
}

func TestSigner(t *testing.T) {
	// Need real cert and chain
	payloadSigner := payload.NewSigner(mustGetNewSigner(t))

	tsaClient, err := mock.NewTSAClient((mock.TSAClientOptions{Time: time.Now()}))
	if err != nil {
		t.Fatal(err)
	}

	testSigner := NewSigner(payloadSigner, tsaClient)

	testPayload := "test payload"

	ociSig, pub, err := testSigner.Sign(context.Background(), strings.NewReader(testPayload))
	if err != nil {
		t.Fatalf("Sign() returned error: %v", err)
	}

	// Verify that the wrapped signer was called.
	verifier, err := signature.LoadVerifier(pub, crypto.SHA256, signature.LoadDefaultSV, nil)
	if err != nil {
		t.Fatalf("signature.LoadVerifier(pub) returned error: %v", err)
	}
	sig, err := ociSig.Signature()
	if err != nil {
		t.Fatalf("ociSig.Signature() returned error: %v", err)
	}
	gotPayload, err := ociSig.Payload()
	if err != nil {
		t.Fatalf("ociSig.Payload() returned error: %v", err)
	}
	if string(gotPayload) != testPayload {
		t.Errorf("ociSig.Payload() returned %q, wanted %q", string(gotPayload), testPayload)
	}
	if err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(gotPayload)); err != nil {
		t.Errorf("VerifySignature() returned error: %v", err)
	}
}

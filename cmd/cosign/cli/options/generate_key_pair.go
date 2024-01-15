//
// Copyright 2021 The Sigstore Authors.
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

package options

import (
	"fmt"
	"strings"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/spf13/cobra"
)

// GenerateKeyPairOptions is the top level wrapper for the generate-key-pair command.
type GenerateKeyPairOptions struct {
	// KMS Key Management Service
	KMS             string
	OutputKeyPrefix string
	KeyType         cosign.SupportedAlgorithmOption
}

var _ Interface = (*GenerateKeyPairOptions)(nil)

// AddFlags implements Interface
func (o *GenerateKeyPairOptions) AddFlags(cmd *cobra.Command) {
	keyAlgorithmTypes := []string{}
	for _, keyAlgorithm := range v1.SupportedAlgorithm_value {
		keyAlgorithmTypes = append(keyAlgorithmTypes, v1.SupportedAlgorithm_name[int32(keyAlgorithm)])
	}
	keyAlgorithmHelp := fmt.Sprintf("algorithm to use for signing (allowed %s) default: %s", strings.Join(keyAlgorithmTypes, ", "), v1.SupportedAlgorithm_ECDSA_SHA2_256_NISTP256.String())
	cmd.Flags().Var(&o.KeyType, "key-algorithm", keyAlgorithmHelp)

	cmd.Flags().StringVar(&o.KMS, "kms", "",
		"create key pair in KMS service to use for signing")
	cmd.Flags().StringVar(&o.OutputKeyPrefix, "output-key-prefix", "cosign",
		"name used for generated .pub and .key files (defaults to `cosign`)")
}

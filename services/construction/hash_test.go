// Copyright 2021 Coinbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package construction

import (
	"context"
	"testing"

	"github.com/coinbase/rosetta-sdk-go/types"
	svcErrors "github.com/maticnetwork/polygon-rosetta/services/errors"
	"github.com/stretchr/testify/assert"
)

func TestConstructionHash(t *testing.T) {
	signed := `{"nonce":"0x6","gasPrice":"0x6d6e2edc00","gas":"0x5208","to":"0x85ad9d1fcf50b72255e4288dca0ad29f5f509409","value":"0xde0b6b3a7640000","input":"0x","v":"0x150f6","r":"0x64d46cc17cbdbcf73b204a6979172eb3148237ecd369181b105e92b0d7fa49a7","s":"0x285063de57245f532a14b13f605bed047a9d20ebfd0db28e01bc8cc9eaac40ee","hash":"0x92ea9280c1653aa9042c7a4d3a608c2149db45064609c18b270c7c73738e2a46"}` //nolint:lll
	txHash := "0x92ea9280c1653aa9042c7a4d3a608c2149db45064609c18b270c7c73738e2a46"

	tests := map[string]struct {
		request          *types.ConstructionHashRequest
		expectedResponse *types.TransactionIdentifierResponse
		expectedError    *types.Error
	}{
		"happy path": {
			request: templateHashRequest(signed),
			expectedResponse: &types.TransactionIdentifierResponse{
				TransactionIdentifier: &types.TransactionIdentifier{Hash: txHash},
			},
		},
		"error: missing transaction": {
			request: &types.ConstructionHashRequest{},
			expectedError: templateError(
				svcErrors.ErrInvalidSignature, "signed transaction value is not provided"),
		},
		"error: invalid transaction": {
			request: templateHashRequest("{}"),
			expectedError: templateError(
				svcErrors.ErrUnableToParseIntermediateResult, "missing required field 'nonce' in transaction"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := APIService{}
			resp, err := service.ConstructionHash(context.Background(), test.request)

			if err != nil {
				assert.Equal(t, test.expectedError, err)
			} else {
				assert.Equal(t, test.expectedResponse, resp)
			}
		})
	}
}

func templateHashRequest(signedTx string) *types.ConstructionHashRequest {
	return &types.ConstructionHashRequest{
		NetworkIdentifier: networkIdentifier,
		SignedTransaction: signedTx,
	}
}

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
	"encoding/hex"
	"testing"

	"github.com/coinbase/rosetta-sdk-go/types"
	svcErrors "github.com/maticnetwork/polygon-rosetta/services/errors"
	"github.com/stretchr/testify/assert"
)

func TestConstructionDerive(t *testing.T) {
	tests := map[string]struct {
		request          *types.ConstructionDeriveRequest
		expectedResponse *types.ConstructionDeriveResponse
		expectedError    *types.Error
	}{
		"happy path": {
			request: templateDeriveRequest("03d0156cec2e01eff9c66e5dbc3c70f98214ec90a25eb43320ebcddc1a94b677f0"),
			expectedResponse: &types.ConstructionDeriveResponse{
				AccountIdentifier: &types.AccountIdentifier{
					Address: "0x156daFC6e9A1304fD5C9AB686acB4B3c802FE3f7",
				},
			},
		},
		"error: missing public key": {
			request: &types.ConstructionDeriveRequest{},
			expectedError: templateError(
				svcErrors.ErrInvalidPublicKey, "public key is not provided"),
		},
		"error: empty public key": {
			request: templateDeriveRequest(""),
			expectedError: templateError(
				svcErrors.ErrUnableToDecompressPubkey, "invalid public key"),
		},
		"error: invalid public key": {
			request: templateDeriveRequest("invalid_public_key"),
			expectedError: templateError(
				svcErrors.ErrUnableToDecompressPubkey, "invalid public key"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := APIService{}
			resp, err := service.ConstructionDerive(context.Background(), test.request)

			if err != nil {
				assert.Equal(t, test.expectedError, err)
			} else {
				assert.Equal(t, test.expectedResponse, resp)
			}
		})
	}
}

func templateDeriveRequest(pubKey string) *types.ConstructionDeriveRequest {
	var bytes []byte
	if len(pubKey) != 0 {
		bytes, _ = hex.DecodeString(pubKey)
	}
	return &types.ConstructionDeriveRequest{
		NetworkIdentifier: networkIdentifier,
		PublicKey: &types.PublicKey{
			Bytes:     bytes,
			CurveType: types.Secp256k1,
		},
	}
}

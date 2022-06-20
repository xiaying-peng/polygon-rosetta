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
	"encoding/json"
	"testing"

	"github.com/coinbase/rosetta-sdk-go/types"
	svcError "github.com/maticnetwork/polygon-rosetta/services/errors"
	"github.com/stretchr/testify/assert"
)

func TestConstructionCombine(t *testing.T) {
	unsignedRaw := `{"from":"0x5aCB42b3cfCD734a57AFF800139ba1354b549159","to":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c","value":"0x3e8","data":"0x","nonce":"0x2","gas_price":"0x0","max_fee_per_gas":"0x59682f15","max_priority_fee_per_gas":"0x59682eff","gas":"0x5208","chain_id":"0x13881"}`                                                                                                                                                                                                                                                                           // nolint
	signedRaw := `{"type":"0x2","nonce":"0x2","gasPrice":null,"maxPriorityFeePerGas":"0x59682eff","maxFeePerGas":"0x59682f15","gas":"0x5208","value":"0x3e8","input":"0x","v":"0x1","r":"0x6afe2f65d311ff2430ca7388335b86e42606ea4728924d91564405df83d2cea5","s":"0x443a04f2d96ea9877ed67f2b45266446ab01de2154c268470f57bb12effa1563","to":"0x3fa177c2e87cb24148ec403921db577d140cc07c","chainId":"0x13881","accessList":[],"hash":"0x554c2edbd04b2be9d1314ef31201e3382eedb24a733f1b15448af2d16252db73"}`                                                                     // nolint
	signaturesRaw := `[{"hex_bytes": "6afe2f65d311ff2430ca7388335b86e42606ea4728924d91564405df83d2cea5443a04f2d96ea9877ed67f2b45266446ab01de2154c268470f57bb12effa156301", "public_key": {"hex_bytes": "0405e82ac561143aafc13ba109677a597c8f797b07417d0addd7a346ad35882b3c4a006620e02127b9a32e90979ff93ecad0a2f577db238163a50023e393e354ff", "curve_type": "secp256k1"}, "signing_payload": {"hex_bytes": "15ff43e2bc6aacc7d0f0ed76eb3102aaf9b1292e2ba07575a4e4f3ddb5b54780", "address": "0x5aCB42b3cfCD734a57AFF800139ba1354b549159"}, "signature_type": "ecdsa_recovery"}]` // nolint
	var signatures []*types.Signature
	_ = json.Unmarshal([]byte(signaturesRaw), &signatures)

	tests := map[string]struct {
		request          *types.ConstructionCombineRequest
		expectedResponse *types.ConstructionCombineResponse
		expectedError    *types.Error
	}{
		"happy path": {
			request: templateConstructCombineRequest(unsignedRaw, signatures),
			expectedResponse: &types.ConstructionCombineResponse{
				SignedTransaction: signedRaw,
			},
		},
		"error: no transaction": {
			request: &types.ConstructionCombineRequest{},
			expectedError: templateError(
				svcError.ErrInvalidTransaction, "transaction data is not provided"),
		},
		"error: no signature": {
			request: templateConstructCombineRequest(unsignedRaw, nil),
			expectedError: templateError(
				svcError.ErrInvalidSignature, "signature is not provided"),
		},
		"error: invalid transaction": {
			request: templateConstructCombineRequest("{}", signatures),
			expectedError: templateError(
				svcError.ErrUnableToParseIntermediateResult, "empty hex string"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := APIService{}

			resp, err := service.ConstructionCombine(context.Background(), test.request)

			if err != nil {
				assert.Equal(t, test.expectedError, err)
			} else {
				assert.Equal(t, test.expectedResponse, resp)
			}
		})
	}
}

func templateConstructCombineRequest(
	unsignedTx string,
	signatures []*types.Signature,
) *types.ConstructionCombineRequest {
	return &types.ConstructionCombineRequest{
		NetworkIdentifier:   networkIdentifier,
		UnsignedTransaction: unsignedTx,
		Signatures:          signatures,
	}
}

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
	unsignedRaw := `{"from":"0xD10a72Cf054650931365Cc44D912a4FD75257058","to":"0x57B414a0332B5CaB885a451c2a28a07d1e9b8a8d","value":"0x9864aac3510d02","data":"0x","nonce":"0x0","gas_price":"0x3b9aca00","gas":"0x5208","chain_id":"0x13881"}`                                                                                                                                                                                                                                                                                                                                                                   // nolint
	signedRaw := `{"type":"0x0","nonce":"0x0","gasPrice":"0x3b9aca00","maxPriorityFeePerGas":null,"maxFeePerGas":null,"gas":"0x5208","value":"0x9864aac3510d02","input":"0x","v":"0x27126","r":"0x303b2ff05024c20f1775dad9a6e8152fa75bec47c051d7fd2e39572fbddd048e","s":"0xf2c494280dfa0465d384280dc918c930aae0874714e893382c16058aadf505","to":"0x57b414a0332b5cab885a451c2a28a07d1e9b8a8d","hash":"0x2500ef3f8531452210cfdfe3c11111e9605a2acdd260ac75c8c3ade30258228e"}`                                                                                                                                       // nolint
	signaturesRaw := `[{"hex_bytes":"303b2ff05024c20f1775dad9a6e8152fa75bec47c051d7fd2e39572fbddd048e00f2c494280dfa0465d384280dc918c930aae0874714e893382c16058aadf50501","signing_payload":{"address":"0xD10a72Cf054650931365Cc44D912a4FD75257058","hex_bytes":"375623b2f9164db0bc050c357fb4e6b57a60ffa1eba0161fe12e96384103218c","account_identifier":{"address":"0xD10a72Cf054650931365Cc44D912a4FD75257058"},"signature_type":"ecdsa_recovery"},"public_key":{"hex_bytes":"0212e9f98d9750e5f74b4b4b00df39074f86c79187943bdb3c5a9c89ffc1ed0188","curve_type":"secp256k1"},"signature_type":"ecdsa_recovery"}]` // nolint
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

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

	svcError "github.com/maticnetwork/polygon-rosetta/services/errors"

	"github.com/maticnetwork/polygon-rosetta/polygon"

	"github.com/coinbase/rosetta-sdk-go/types"
	"github.com/stretchr/testify/assert"
)

var (
	unsignedMaticTransferTx            = `{"from":"0x966fbC4E1F3a938Cf7798695C3244d9C7C190015","to":"0xefD3dc58D60aF3295B92ecd484CAEB3A2f30b3e7","value":"0x134653c","data":"0x","nonce":"0x43","gas_price":"0x12a05f200","gas":"0x5208","chain_id":"0x13881"}`                                                                                                                                                                                                                                                                                                      //nolint:lll
	signedMaticTransferTx              = `{"nonce":"0x43","gasPrice":"0x12a05f200","gas":"0x5208","to":"0xefd3dc58d60af3295b92ecd484caeb3a2f30b3e7","value":"0x134653c","input":"0x","v":"0x27125","r":"0x733a6097719aab45c9209c77e967f057c60036360d839a55316eaec60dbedcd9","s":"0x1fe4a59a206403cd09e0ff5b29f5062abb784c003590f84b7bb3daa4e0ade039","hash":"0xa4984c3f6767ec4465f4b11652a3b60fed1f006096f381aba5cf4800a30c5a53"}`                                                                                                                                   //nolint:lll
	unsignedERC20TransferTx            = `{"from":"0x966fbC4E1F3a938Cf7798695C3244d9C7C190015","to":"0x2d7882beDcbfDDce29Ba99965dd3cdF7fcB10A1e","value":"0x0","data":"0xa9059cbb000000000000000000000000efd3dc58d60af3295b92ecd484caeb3a2f30b3e7000000000000000000000000000000000000000000000000000000000134653c","nonce":"0x43","gas_price":"0x12a05f200","gas":"0xfde8","chain_id":"0x13881"}`                                                                                                                                                                    //nolint:lll
	signedERC20TransferTx              = `{"nonce":"0x43","gasPrice":"0x12a05f200","gas":"0xfde8","to":"0x2d7882bedcbfddce29ba99965dd3cdf7fcb10a1e","value":"0x0","input":"0xa9059cbb000000000000000000000000efd3dc58d60af3295b92ecd484caeb3a2f30b3e7000000000000000000000000000000000000000000000000000000000134653c","v":"0x27126","r":"0x66705f88684114cedeaa1d3dca1f1613591e1dae270cd3eafcaaa7c772c28093","s":"0x4e7f3d52f236cf80af661f4465416ac6954f0e65f60f4644bc97f2085e439fd7","hash":"0xcc3fb58789635d41d025d57ca3d973354bdb136b1812e63df6f0e9912ed1c608"}` //nolint:lll
	unsignedERC20TransferTxInvalidData = `{"from":"0x966fbC4E1F3a938Cf7798695C3244d9C7C190015","to":"0x2d7882beDcbfDDce29Ba99965dd3cdF7fcB10A1e","value":"0x0","data":"0xaaaaaaaa000000000000000000000000efd3dc58d60af3295b92ecd484caeb3a2f30b3e7000000000000000000000000000000000000000000000000000000000134653c","nonce":"0x43","gas_price":"0x12a05f200","gas":"0xfde8","chain_id":"0x13881"}`                                                                                                                                                                    //nolint:lll
	unsignedMaticTransferTxInvalidFrom = `{"from":"invalid_from","to":"0xefD3dc58D60aF3295B92ecd484CAEB3A2f30b3e7","value":"0x134653c","data":"0x","nonce":"0x43","gas_price":"0x12a05f200","gas":"0x5208","chain_id":"0x13881"}`                                                                                                                                                                                                                                                                                                                                    //nolint:lll
	unsignedMaticTransferTxInvalidTo   = `{"from":"0x966fbC4E1F3a938Cf7798695C3244d9C7C190015","to":"invalid_to","value":"0x134653c","data":"0x","nonce":"0x43","gas_price":"0x12a05f200","gas":"0x5208","chain_id":"0x13881"}`                                                                                                                                                                                                                                                                                                                                      //nolint:lll
)

func TestParse(t *testing.T) {
	tests := map[string]struct {
		request          *types.ConstructionParseRequest
		expectedResponse *types.ConstructionParseResponse
		expectedError    *types.Error
	}{
		"happy path: unsigned Matic transfer tx": {
			request: &types.ConstructionParseRequest{
				NetworkIdentifier: networkIdentifier,
				Signed:            false,
				Transaction:       unsignedMaticTransferTx,
			},
			expectedResponse: &types.ConstructionParseResponse{
				Operations:               templateOperations(transferValue, polygon.Currency),
				AccountIdentifierSigners: []*types.AccountIdentifier{},
				Metadata: map[string]interface{}{
					"nonce":     transferNonceHex,
					"gas_price": transferGasPriceHex,
					"gas_limit": transferGasLimitHex,
					"chain_id":  chainIDHex,
				},
			},
		},
		"happy path: signed Matic transfer tx": {
			request: &types.ConstructionParseRequest{
				NetworkIdentifier: networkIdentifier,
				Signed:            true,
				Transaction:       signedMaticTransferTx,
			},
			expectedResponse: &types.ConstructionParseResponse{
				Operations: templateOperations(transferValue, polygon.Currency),
				AccountIdentifierSigners: []*types.AccountIdentifier{
					{
						Address: fromAddress,
					},
				},
				Metadata: map[string]interface{}{
					"nonce":     transferNonceHex,
					"gas_price": transferGasPriceHex,
					"gas_limit": transferGasLimitHex,
					"chain_id":  chainIDHex,
				},
			},
		},
		"happy path: unsigned ERC20 transfer tx": {
			request: &types.ConstructionParseRequest{
				NetworkIdentifier: networkIdentifier,
				Signed:            false,
				Transaction:       unsignedERC20TransferTx,
			},
			expectedResponse: &types.ConstructionParseResponse{
				Operations: templateOperations(transferValue, &types.Currency{
					Symbol:   "ERC20",
					Decimals: 18,
					Metadata: map[string]interface{}{
						"token_address": tokenContractAddress,
					},
				}),
				AccountIdentifierSigners: []*types.AccountIdentifier{},
				Metadata: map[string]interface{}{
					"nonce":     transferNonceHex,
					"gas_price": transferGasPriceHex,
					"gas_limit": transferGasLimitERC20Hex,
					"chain_id":  chainIDHex,
				},
			},
		},
		"happy path: signed ERC20 transfer tx": {
			request: &types.ConstructionParseRequest{
				NetworkIdentifier: networkIdentifier,
				Signed:            true,
				Transaction:       signedERC20TransferTx,
			},
			expectedResponse: &types.ConstructionParseResponse{
				Operations: templateOperations(transferValue, &types.Currency{
					Symbol:   "ERC20",
					Decimals: 18,
					Metadata: map[string]interface{}{
						"token_address": tokenContractAddress,
					},
				}),
				AccountIdentifierSigners: []*types.AccountIdentifier{
					{
						Address: fromAddress,
					},
				},
				Metadata: map[string]interface{}{
					"nonce":     transferNonceHex,
					"gas_price": transferGasPriceHex,
					"gas_limit": transferGasLimitERC20Hex,
					"chain_id":  chainIDHex,
				},
			},
		},
		"error: empty transaction": {
			request: &types.ConstructionParseRequest{
				NetworkIdentifier: networkIdentifier,
				Signed:            false,
				Transaction:       "",
			},
			expectedError: templateError(
				svcError.ErrUnableToParseIntermediateResult, "unexpected end of JSON input"),
		},
		// TODO: Add logic for generic call
		// "error: unable to parse transaction": {
		// 	request: &types.ConstructionParseRequest{
		// 		NetworkIdentifier: networkIdentifier,
		// 		Signed:            false,
		// 		Transaction:       unsignedERC20TransferTxInvalidData,
		// 	},
		// 	expectedError: templateError(
		// 		svcError.ErrUnableToParseTransaction, "invalid method id"),
		// },
		"error: invalid from address": {
			request: &types.ConstructionParseRequest{
				NetworkIdentifier: networkIdentifier,
				Signed:            false,
				Transaction:       unsignedMaticTransferTxInvalidFrom,
			},
			expectedError: templateError(
				svcError.ErrInvalidAddress, "invalid_from is not a valid address"),
		},
		"error: invalid to address": {
			request: &types.ConstructionParseRequest{
				NetworkIdentifier: networkIdentifier,
				Signed:            false,
				Transaction:       unsignedMaticTransferTxInvalidTo,
			},
			expectedError: templateError(
				svcError.ErrInvalidAddress, "invalid_to is not a valid address"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := &APIService{}
			resp, err := service.ConstructionParse(context.Background(), test.request)

			if err != nil {
				assert.Equal(t, test.expectedError, err)
			} else {
				assert.Equal(t, test.expectedResponse, resp)
			}
		})
	}
}

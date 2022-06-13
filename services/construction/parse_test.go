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
	"math/big"
	"testing"

	svcError "github.com/maticnetwork/polygon-rosetta/services/errors"

	"github.com/maticnetwork/polygon-rosetta/polygon"

	"github.com/coinbase/rosetta-sdk-go/types"
	"github.com/stretchr/testify/assert"
)

var (
	unsignedMaticTransferTx            = `{"from":"0x5aCB42b3cfCD734a57AFF800139ba1354b549159","to":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c","value":"0x3e8","data":"0x","nonce":"0x2","max_fee_per_gas":"0x59682f15","max_priority_fee_per_gas":"0x59682eff","gas":"0x5208","chain_id":"0x13881"}`                                                                                                                                                                                                                                                                                                      //nolint:lll
	signedMaticTransferTx              = `{"type":"0x2","nonce":"0x2","gasPrice":null,"maxPriorityFeePerGas":"0x59682eff","maxFeePerGas":"0x59682f15","gas":"0x5208","value":"0x3e8","input":"0x","v":"0x1","r":"0x6afe2f65d311ff2430ca7388335b86e42606ea4728924d91564405df83d2cea5","s":"0x443a04f2d96ea9877ed67f2b45266446ab01de2154c268470f57bb12effa1563","to":"0x3fa177c2e87cb24148ec403921db577d140cc07c","chainId":"0x13881","accessList":[],"hash":"0x554c2edbd04b2be9d1314ef31201e3382eedb24a733f1b15448af2d16252db73"}`                                                                                                                                   //nolint:lll
	unsignedERC20TransferTx            = `{"from":"0x5aCB42b3cfCD734a57AFF800139ba1354b549159","to":"0x2d7882beDcbfDDce29Ba99965dd3cdF7fcB10A1e","value":"0x0","data":"0xa9059cbb0000000000000000000000003fa177c2e87cb24148ec403921db577d140cc07c0000000000000000000000000000000000000000000000000000000000000064","nonce":"0x2","max_fee_per_gas":"0x9502f914","max_priority_fee_per_gas":"0x9502f900","gas":"0xb2cb","chain_id":"0x13881"}`                                                                                                                                                                    //nolint:lll
	signedERC20TransferTx              = `{"type":"0x2","nonce":"0x2","gasPrice":null,"maxPriorityFeePerGas":"0x9502f900","maxFeePerGas":"0x9502f914","gas":"0xb2cb","value":"0x0","input":"0xa9059cbb0000000000000000000000003fa177c2e87cb24148ec403921db577d140cc07c0000000000000000000000000000000000000000000000000000000000000064","v":"0x1","r":"0x2a8799b115741f62d5da931a53428ad1e3bf3055e9ea8427ce196a44cc590fca","s":"0x4779ab01b496c8b27e19efd24817557609b50da0d7e1a3790c435ca2225b43ae","to":"0x2d7882bedcbfddce29ba99965dd3cdf7fcb10a1e","chainId":"0x13881","accessList":[],"hash":"0xaa0f2056a79315e60a2012aee5f582692817e12153c6e45f57215f848893ec9e"}`  //nolint:lll
	unsignedERC20TransferTxInvalidData = `"{"from":"0x5aCB42b3cfCD734a57AFF800139ba1354b549159","to":"0x2d7882beDcbfDDce29Ba99965dd3cdF7fcB10A1e","value":"0x0","data":"0xaaaaaaaa000000000000000000000000efd3dc58d60af3295b92ecd484caeb3a2f30b3e7000000000000000000000000000000000000000000000000000000000134653c","nonce":"0x2","max_fee_per_gas":"0x9502f914","max_priority_fee_per_gas":"0x9502f900","gas":"0xb2cb","chain_id":"0x13881"}"`                                                                                                                                                                   //nolint:lll
	unsignedMaticTransferTxInvalidFrom = `{"from":"invalid_from","to":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c","value":"0x3e8","data":"0x","nonce":"0x2","max_fee_per_gas":"0x59682f15","max_priority_fee_per_gas":"0x59682eff","gas":"0x5208","chain_id":"0x13881"}`                                                                                                                                                                                                                                                                                                                                    //nolint:lll
	unsignedMaticTransferTxInvalidTo   = `{"from":"0x5aCB42b3cfCD734a57AFF800139ba1354b549159","to":"invalid_to","value":"0x3e8","data":"0x","nonce":"0x2","max_fee_per_gas":"0x59682f15","max_priority_fee_per_gas":"0x59682eff","gas":"0x5208","chain_id":"0x13881"}`                                                                                                                                                                                                                                                                                                                                      //nolint:lll

	parseFromAddress = "0x5aCB42b3cfCD734a57AFF800139ba1354b549159"
	parseToAddress = "0x3Fa177c2E87Cb24148EC403921dB577d140CC07c"
	parseTokenContractAddress = "0x2d7882beDcbfDDce29Ba99965dd3cdF7fcB10A1e"

	gasCapHex   = "0x59682f15"
	gasTipHex   = "0x59682eff"
	nonceHex = "0x2"
	value = uint64(1000)

	gasCapERC20Hex   = "0x9502f914"
	gasTipERC20Hex   = "0x9502f900"
	gasLimitERC20Hex = "0xb2cb"
	nonceERC20Hex = "0x2"
	valueERC20 = uint64(100)
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
				Operations:               parseTemplateOperations(parseFromAddress, parseToAddress, value, polygon.Currency),
				AccountIdentifierSigners: []*types.AccountIdentifier{},
				Metadata: map[string]interface{}{
					"nonce":     nonceHex,
					"gas_limit": transferGasLimitHex,
					"gas_cap":   gasCapHex,
					"gas_tip":   gasTipHex,
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
				Operations: parseTemplateOperations(parseFromAddress, parseToAddress, value, polygon.Currency),
				AccountIdentifierSigners: []*types.AccountIdentifier{
					{
						Address: parseFromAddress,
					},
				},
				Metadata: map[string]interface{}{
					"nonce":     nonceHex,
					"gas_limit": transferGasLimitHex,
					"gas_cap":   gasCapHex,
					"gas_tip":   gasTipHex,
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
				Operations: parseTemplateOperations(parseFromAddress, parseToAddress, valueERC20, &types.Currency{
					Symbol:   "ERC20",
					Decimals: 18,
					Metadata: map[string]interface{}{
						"token_address": parseTokenContractAddress,
					},
				}),
				AccountIdentifierSigners: []*types.AccountIdentifier{},
				Metadata: map[string]interface{}{
					"nonce":     nonceERC20Hex,
					"gas_limit": gasLimitERC20Hex,
					"gas_cap":   gasCapERC20Hex,
					"gas_tip":   gasTipERC20Hex,
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
				Operations: parseTemplateOperations(parseFromAddress, parseToAddress, valueERC20, &types.Currency{
					Symbol:   "ERC20",
					Decimals: 18,
					Metadata: map[string]interface{}{
						"token_address": parseTokenContractAddress,
					},
				}),
				AccountIdentifierSigners: []*types.AccountIdentifier{
					{
						Address: parseFromAddress,
					},
				},
				Metadata: map[string]interface{}{
					"nonce":     nonceERC20Hex,
					"gas_limit": gasLimitERC20Hex,
					"gas_cap":   gasCapERC20Hex,
					"gas_tip":   gasTipERC20Hex,
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

func parseTemplateOperations(fromAddress string, toAddress string, amount uint64, currency *types.Currency) []*types.Operation {
	return rosettaOperations(
		fromAddress,
		toAddress,
		big.NewInt(int64(amount)),
		currency,
	)
}

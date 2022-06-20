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
	"fmt"
	"math/big"
	"testing"

	svcErrors "github.com/maticnetwork/polygon-rosetta/services/errors"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/params"
	"github.com/maticnetwork/polygon-rosetta/configuration"
	"github.com/stretchr/testify/assert"

	"github.com/coinbase/rosetta-sdk-go/types"
	"github.com/maticnetwork/polygon-rosetta/polygon"
)

var (
	invalidTransferData = "0xaaaaaaaa000000000000000000000000efd3dc58d60af3295b92ecd484caeb3a2f30b3e70000000000000000000000000000000000000000000000000000000000000001" // nolint

)

func TestPayloads(t *testing.T) {
	tests := map[string]struct {
		request          *types.ConstructionPayloadsRequest
		expectedResponse *types.ConstructionPayloadsResponse
		expectedError    *types.Error
	}{
		"happy path: native currency": {
			request: templateConstructionPayloadsRequest(
				templateOperations(transferValue, polygon.Currency),
				templateNativeCurrencyTxMetadata(transferValueHex),
			),
			expectedResponse: templateConstructionPayloadsResponse(
				templateNativeCurrencyUnsigned(),
				"0x3caf34daaaf7bfd3a8fb58a7a351b354df0945bba7723f70d1bbff5bcf4b83a5",
			),
		},
		"happy path: ERC20 currency": {
			request: templateConstructionPayloadsRequest(
				templateOperations(transferValue, &types.Currency{
					Symbol:   "USDC",
					Decimals: 18,
					Metadata: map[string]interface{}{
						"token_address": tokenContractAddress,
					},
				}),
				templateERC20CurrencyTxMetadata(),
			),
			expectedResponse: templateConstructionPayloadsResponse(
				templateERC20CurrencyUnsigned(),
				"0xc3ded208fa7991852eab06cae487e5fa193bffe8358fe3a5b6a3a3cce8c7e74b",
			),
		},
		"happy path: Generic contract call": {
			request: templateConstructionPayloadsRequest(
				templateOperations(transferValue, &types.Currency{
					Symbol:   "USDC",
					Decimals: 18,
					Metadata: map[string]interface{}{
						"token_address": tokenContractAddress,
					},
				}),
				templateGenericContractCallTxMetadata(),
			),
			expectedResponse: templateConstructionPayloadsResponse(
				templateGenericContractCallUnsigned(),
				"0xaf70e3931747fca4b94ef94445ffd8e20af420c83eeec7a6fe5156e7733fb242",
			),
		},
		"error: bad request: native currency mismatch destination address": {
			request: templateConstructionPayloadsRequest(
				func() []*types.Operation {
					operations := templateOperations(transferValue, polygon.Currency)
					operations[1].Account.Address = "0x29c5bCD4E896dd03F1d5316F94A0b6c6605Fd62D" // a random to address
					return operations
				}(),
				templateNativeCurrencyTxMetadata(transferValueHex),
			),
			expectedError: templateError(svcErrors.ErrBadRequest, "mismatch destination address"),
		},
		"error: bad request: native currency mismatch amount": {
			request: templateConstructionPayloadsRequest(
				templateOperations(transferValue+2, polygon.Currency),
				templateNativeCurrencyTxMetadata(transferValueHex),
			),
			expectedError: templateError(svcErrors.ErrBadRequest, "mismatch transfer value"),
		},
		"error: bad request: ERC20 currency mismatch amount": {
			request: templateConstructionPayloadsRequest(
				templateOperations(transferValue+2, polygon.Currency),
				templateERC20CurrencyTxMetadata(),
			),
			expectedError: templateError(svcErrors.ErrBadRequest, "mismatch transfer value"),
		},
		"error: bad request: ERC20 currency mismatch destination address": {
			request: templateConstructionPayloadsRequest(
				func() []*types.Operation {
					operations := templateOperations(transferValue, polygon.Currency)
					operations[1].Account.Address = "0x29c5bCD4E896dd03F1d5316F94A0b6c6605Fd62D" // a random to address
					return operations
				}(),
				templateERC20CurrencyTxMetadata(),
			),
			expectedError: templateError(svcErrors.ErrBadRequest, "mismatch destination address"),
		},
		"error: bad request: ERC20 currency invalid metadata value": {
			request: templateConstructionPayloadsRequest(
				templateOperations(transferValue, polygon.Currency),
				func() map[string]interface{} {
					data := templateERC20CurrencyTxMetadata()
					data["value"] = "0x1"
					return data
				}(),
			),
			expectedError: templateError(svcErrors.ErrBadRequest, "invalid metadata value"),
		},
		"error: bad request: ERC20 currency invalid method id": {
			request: templateConstructionPayloadsRequest(
				templateOperations(transferValue, polygon.Currency),
				func() map[string]interface{} {
					data := templateERC20CurrencyTxMetadata()
					data["data"] = invalidTransferData
					return data
				}(),
			),
			expectedError: templateError(svcErrors.ErrBadRequest, "invalid data value"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := &APIService{
				config: &configuration.Configuration{
					Params: &params.ChainConfig{ChainID: big.NewInt(int64(chainID))},
				},
			}
			resp, err := service.ConstructionPayloads(context.Background(), test.request)

			if err != nil {
				assert.Equal(t, test.expectedError, err)
			} else {
				assert.Equal(t, test.expectedResponse, resp)
			}
		})
	}
}

func templateConstructionPayloadsRequest(
	operations []*types.Operation,
	metadata map[string]interface{},
) *types.ConstructionPayloadsRequest {
	return &types.ConstructionPayloadsRequest{
		NetworkIdentifier: networkIdentifier,
		Operations:        operations,
		Metadata:          metadata,
	}
}

func templateConstructionPayloadsResponse(
	unsigned string,
	txHash string,
) *types.ConstructionPayloadsResponse {
	bytes, _ := hexutil.Decode(txHash)
	return &types.ConstructionPayloadsResponse{
		UnsignedTransaction: unsigned,
		Payloads: []*types.SigningPayload{
			{
				AccountIdentifier: &types.AccountIdentifier{Address: metadataFrom},
				Bytes:             bytes,
				SignatureType:     types.EcdsaRecovery,
			},
		},
	}
}

func templateNativeCurrencyTxMetadata(amount string) map[string]interface{} {
	return map[string]interface{}{
		"nonce":     transferNonceHex,
		"to":        metadataTo,
		"value":     amount,
		"gas_limit": transferGasLimitHex,
		"gas_cap":   transferGasCapWithTipHex,
		"gas_tip":   transferGasTipHex,
	}
}

func templateERC20CurrencyTxMetadata() map[string]interface{} {
	return map[string]interface{}{
		"nonce":     transferNonceHex,
		"to":        tokenContractAddress,
		"value":     "0x0",
		"gas_limit": transferGasLimitERC20Hex,
		"gas_cap":   transferGasCapWithTipHex,
		"gas_tip":   transferGasTipHex,
		"data":      metadataData,
	}
}

func templateNativeCurrencyUnsigned() string {
	return fmt.Sprintf(
		`{"from":"%s","to":"%s","value":"%s","data":"%s","nonce":"%s","max_fee_per_gas":"%s","max_priority_fee_per_gas":"%s","gas":"%s","chain_id":"%s"}`, //nolint:lll
		metadataFrom,
		metadataTo,
		transferValueHex,
		"0x",
		transferNonceHex,
		transferGasCapWithTipHex,
		transferGasTipHex,
		transferGasLimitHex,
		chainIDHex,
	)
}

func templateERC20CurrencyUnsigned() string {
	return fmt.Sprintf(
		`{"from":"%s","to":"%s","value":"%s","data":"%s","nonce":"%s","max_fee_per_gas":"%s","max_priority_fee_per_gas":"%s","gas":"%s","chain_id":"%s"}`, //nolint:lll
		metadataFrom,
		tokenContractAddress,
		"0x0",
		metadataData,
		transferNonceHex,
		transferGasCapWithTipHex,
		transferGasTipHex,
		transferGasLimitERC20Hex,
		chainIDHex,
	)
}

func templateGenericContractCallTxMetadata() map[string]interface{} {
	return map[string]interface{}{
		"nonce":            transferNonceHex,
		"to":               tokenContractAddress,
		"value":            "0x0",
		"gas_limit":        transferGasLimitERC20Hex,
		"gas_cap":          transferGasCapWithTipHex,
		"gas_tip":          transferGasTipHex,
		"data":             metadataGenericData,
		"method_signature": "approve(address,uint256)",
		"method_args":      []interface{}{"0xD10a72Cf054650931365Cc44D912a4FD75257058", "1000"},
	}
}

func templateGenericContractCallUnsigned() string {
	return fmt.Sprintf(
		`{"from":"%s","to":"%s","value":"%s","data":"%s","nonce":"%s","max_fee_per_gas":"%s","max_priority_fee_per_gas":"%s","gas":"%s","chain_id":"%s"}`, //nolint:lll
		metadataFrom,
		tokenContractAddress,
		"0x0",
		metadataGenericData,
		transferNonceHex,
		transferGasCapWithTipHex,
		transferGasTipHex,
		transferGasLimitERC20Hex,
		chainIDHex,
	)
}

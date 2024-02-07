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

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/xiaying-peng/polygon-rosetta/configuration"
	mocks "github.com/xiaying-peng/polygon-rosetta/mocks/services"
	"github.com/xiaying-peng/polygon-rosetta/polygon"
	"github.com/xiaying-peng/polygon-rosetta/services/errors"
	"github.com/stretchr/testify/assert"
)

var (
	metadataFrom              = fromAddress
	metadataTo                = toAddress
	metadataData              = transferData
	metadataGenericData       = "0x095ea7b3000000000000000000000000d10a72cf054650931365cc44d912a4fd7525705800000000000000000000000000000000000000000000000000000000000003e8"
	maticTokenContract        = "0x0000000000000000000000000000000000001010"
	metadataMaticWithdrawData = "0x2e1a7d4d0000000000000000000000000000000000000000000000000000000005f5e100"
)

func TestMetadata_Offline(t *testing.T) {
	t.Run("unavailable in offline mode", func(t *testing.T) {
		service := APIService{
			config: &configuration.Configuration{Mode: configuration.Offline},
		}

		resp, err := service.ConstructionMetadata(
			context.Background(),
			&types.ConstructionMetadataRequest{},
		)
		assert.Nil(t, resp)
		assert.Equal(t, errors.ErrUnavailableOffline.Code, err.Code)
	})
}

func TestMetadata(t *testing.T) {
	var tests = map[string]struct {
		options          map[string]interface{}
		mocks            func(context.Context, *mocks.Client)
		expectedResponse *types.ConstructionMetadataResponse
		expectedError    *types.Error
	}{
		"happy path: native currency with nonce": {
			options: map[string]interface{}{
				"from":  metadataFrom,
				"to":    metadataTo,
				"value": transferValueHex,
				"nonce": transferNonceHex2,
			},
			expectedResponse: &types.ConstructionMetadataResponse{
				Metadata: map[string]interface{}{
					"to":        metadataTo,
					"value":     transferValueHex,
					"nonce":     transferNonceHex2,
					"gas_limit": transferGasLimitHex,
					"gas_cap":   transferGasCapWithTipHex,
					"gas_tip":   transferGasTipMultipliedHex,
				},
				SuggestedFee: []*types.Amount{
					{
						Value:    fmt.Sprintf("%d", transferGasCapWithTip*transferGasLimit),
						Currency: polygon.Currency,
					},
				},
			},
			mocks: func(ctx context.Context, client *mocks.Client) {
				var blockNum *big.Int = nil

				client.On("BlockHeader", ctx, blockNum).
					Return(&header, nil)

				client.On("SuggestGasTipCap", ctx).
					Return(big.NewInt(int64(transferGasTip)), nil)

			},
		},
		"happy path: native currency without nonce": {
			options: map[string]interface{}{
				"from":  metadataFrom,
				"to":    metadataTo,
				"value": transferValueHex,
			},
			mocks: func(ctx context.Context, client *mocks.Client) {

				client.On("PendingNonceAt", ctx, common.HexToAddress(metadataFrom)).
					Return(transferNonce, nil)

				var blockNum *big.Int = nil

				client.On("BlockHeader", ctx, blockNum).
					Return(&header, nil)

				client.On("SuggestGasTipCap", ctx).
					Return(big.NewInt(int64(transferGasTip)), nil)

			},
			expectedResponse: &types.ConstructionMetadataResponse{
				Metadata: map[string]interface{}{
					"to":        metadataTo,
					"value":     transferValueHex,
					"nonce":     transferNonceHex,
					"gas_limit": transferGasLimitHex,
					"gas_cap":   transferGasCapWithTipHex,
					"gas_tip":   transferGasTipMultipliedHex,
				},
				SuggestedFee: []*types.Amount{
					{
						Value:    fmt.Sprintf("%d", transferGasCapWithTip*transferGasLimit),
						Currency: polygon.Currency,
					},
				},
			},
		},
		"happy path: native currency with low estimated gas tip overridden to 40 gwei": {
			options: map[string]interface{}{
				"from":  metadataFrom,
				"to":    metadataTo,
				"value": transferValueHex,
				"nonce": transferNonceHex2,
			},
			expectedResponse: &types.ConstructionMetadataResponse{
				Metadata: map[string]interface{}{
					"to":        metadataTo,
					"value":     transferValueHex,
					"nonce":     transferNonceHex2,
					"gas_limit": transferGasLimitHex,
					"gas_cap":   transferGasCapWithTipHex,
					"gas_tip":   transferGasTipMultipliedHex,
				},
				SuggestedFee: []*types.Amount{
					{
						Value:    fmt.Sprintf("%d", transferGasCapWithTip*transferGasLimit),
						Currency: polygon.Currency,
					},
				},
			},
			mocks: func(ctx context.Context, client *mocks.Client) {
				var blockNum *big.Int = nil

				client.On("BlockHeader", ctx, blockNum).
					Return(&header, nil)

				client.On("SuggestGasTipCap", ctx).
					Return(big.NewInt(int64(transferGasTipEstimate)), nil)

			},
		},
		"happy path: ERC20 currency with nonce": {
			options: map[string]interface{}{
				"from":          metadataFrom,
				"to":            metadataTo,
				"value":         "0x0",
				"nonce":         transferNonceHex2,
				"token_address": tokenContractAddress,
				"data":          metadataData,
			},
			mocks: func(ctx context.Context, client *mocks.Client) {

				to := common.HexToAddress(tokenContractAddress)
				dataBytes, _ := hexutil.Decode(metadataData)
				client.On("EstimateGas", ctx, ethereum.CallMsg{
					From: common.HexToAddress(metadataFrom),
					To:   &to,
					Data: dataBytes,
				}).Return(transferGasLimitERC20, nil)

				var blockNum *big.Int = nil

				client.On("BlockHeader", ctx, blockNum).
					Return(&header, nil)

				client.On("SuggestGasTipCap", ctx).
					Return(big.NewInt(int64(transferGasTip)), nil)

			},
			expectedResponse: &types.ConstructionMetadataResponse{
				Metadata: map[string]interface{}{
					"to":        tokenContractAddress,
					"value":     "0x0",
					"nonce":     transferNonceHex2,
					"gas_limit": transferGasLimitERC20Hex,
					"gas_cap":   transferGasCapWithTipHex,
					"gas_tip":   transferGasTipMultipliedHex,
					"data":      metadataData,
				},
				SuggestedFee: []*types.Amount{
					{
						Value:    fmt.Sprintf("%d", transferGasCapWithTip*transferGasLimitERC20),
						Currency: polygon.Currency,
					},
				},
			},
		},
		"happy path: Generic contract call metadata": {
			options: map[string]interface{}{
				"from":             metadataFrom,
				"to":               metadataTo,
				"value":            "0x0",
				"nonce":            transferNonceHex2,
				"contract_address": tokenContractAddress,
				"data":             metadataGenericData,
				"method_signature": "approve(address,uint256)",
				"method_args":      []string{"0xD10a72Cf054650931365Cc44D912a4FD75257058", "1000"},
			},
			mocks: func(ctx context.Context, client *mocks.Client) {

				to := common.HexToAddress(tokenContractAddress)
				dataBytes, _ := hexutil.Decode(metadataGenericData)
				client.On("EstimateGas", ctx, ethereum.CallMsg{
					From: common.HexToAddress(metadataFrom),
					To:   &to,
					Data: dataBytes,
				}).Return(transferGasLimitERC20, nil)

				var blockNum *big.Int = nil

				client.On("BlockHeader", ctx, blockNum).
					Return(&header, nil)

				client.On("SuggestGasTipCap", ctx).
					Return(big.NewInt(int64(transferGasTip)), nil)

			},
			expectedResponse: &types.ConstructionMetadataResponse{
				Metadata: map[string]interface{}{
					"to":               tokenContractAddress,
					"value":            "0x0",
					"nonce":            transferNonceHex2,
					"gas_limit":        transferGasLimitERC20Hex,
					"gas_cap":          transferGasCapWithTipHex,
					"gas_tip":          transferGasTipMultipliedHex,
					"data":             metadataGenericData,
					"method_signature": "approve(address,uint256)",
					"method_args":      []interface{}{"0xD10a72Cf054650931365Cc44D912a4FD75257058", "1000"},
				},
				SuggestedFee: []*types.Amount{
					{
						Value:    fmt.Sprintf("%d", transferGasCapWithTip*transferGasLimitERC20),
						Currency: polygon.Currency,
					},
				},
			},
		},
		"happy path: Generic contract call with native amount": {
			options: map[string]interface{}{
				"from":             metadataFrom,
				"to":               maticTokenContract,
				"value":            "0x5f5e100",
				"nonce":            transferNonceHex2,
				"contract_address": maticTokenContract,
				"data":             metadataMaticWithdrawData,
				"method_signature": "withdraw(uint256)",
				"method_args":      []string{"100000000"},
			},
			mocks: func(ctx context.Context, client *mocks.Client) {

				to := common.HexToAddress(maticTokenContract)
				dataBytes, _ := hexutil.Decode(metadataMaticWithdrawData)
				client.On("EstimateGas", ctx, ethereum.CallMsg{
					From:  common.HexToAddress(metadataFrom),
					To:    &to,
					Data:  dataBytes,
					Value: big.NewInt(100000000),
				}).Return(transferGasLimitERC20, nil)

				var blockNum *big.Int = nil

				client.On("BlockHeader", ctx, blockNum).
					Return(&header, nil)

				client.On("SuggestGasTipCap", ctx).
					Return(big.NewInt(int64(transferGasTip)), nil)
			},
			expectedResponse: &types.ConstructionMetadataResponse{
				Metadata: map[string]interface{}{
					"to":               maticTokenContract,
					"value":            "0x5f5e100",
					"nonce":            transferNonceHex2,
					"gas_limit":        transferGasLimitERC20Hex,
					"gas_cap":          transferGasCapWithTipHex,
					"gas_tip":          transferGasTipMultipliedHex,
					"data":             metadataMaticWithdrawData,
					"method_signature": "withdraw(uint256)",
					"method_args":      []interface{}{"100000000"},
				},
				SuggestedFee: []*types.Amount{
					{
						Value:    fmt.Sprintf("%d", transferGasCapWithTip*transferGasLimitERC20),
						Currency: polygon.Currency,
					},
				},
			},
		},
		"error: missing source address": {
			options: map[string]interface{}{
				"to":    metadataTo,
				"nonce": transferNonceHex2,
				"value": transferValueHex,
			},
			expectedResponse: nil,
			expectedError: templateError(
				errors.ErrInvalidAddress, "source address is not provided"),
		},
		"error: invalid source address": {
			options: map[string]interface{}{
				"from":  "invalid_from",
				"to":    metadataTo,
				"nonce": transferNonceHex2,
				"value": transferValueHex,
			},
			expectedResponse: nil,
			expectedError: templateError(
				errors.ErrInvalidAddress, "invalid_from is not a valid address"),
		},
		"error: missing destination address": {
			options: map[string]interface{}{
				"from":  metadataFrom,
				"nonce": transferNonceHex,
				"value": transferValueHex,
			},
			expectedResponse: nil,
			expectedError: templateError(
				errors.ErrInvalidAddress, "destination address is not provided"),
		},
		"error: invalid destination address": {
			options: map[string]interface{}{
				"from":  metadataFrom,
				"to":    "invalid_to",
				"nonce": transferNonceHex,
				"value": transferValueHex,
			},
			expectedResponse: nil,
			expectedError: templateError(
				errors.ErrInvalidAddress, "invalid_to is not a valid address"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mockClient := &mocks.Client{}
			service := NewAPIService(
				&configuration.Configuration{Mode: configuration.Online},
				mockClient,
			)

			if test.mocks != nil {
				test.mocks(context.Background(), mockClient)
			}

			resp, err := service.ConstructionMetadata(context.Background(), &types.ConstructionMetadataRequest{
				NetworkIdentifier: networkIdentifier,
				Options:           test.options,
			})

			if err != nil {
				assert.Equal(t, test.expectedError, err)
			} else {
				assert.Equal(t, test.expectedResponse, resp)
			}
		})
	}
}

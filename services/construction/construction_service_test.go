// Copyright 2020 Coinbase, Inc.
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
	"encoding/json"
	"math/big"
	"testing"

	EthTypes "github.com/ethereum/go-ethereum/core/types"

	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/ethereum/go-ethereum/params"

	"github.com/xiaying-peng/polygon-rosetta/configuration"
	mocks "github.com/xiaying-peng/polygon-rosetta/mocks/services"
	"github.com/xiaying-peng/polygon-rosetta/polygon"

	"github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var (
	//// Network-related variables
	networkIdentifier = &types.NetworkIdentifier{
		Network:    polygon.TestnetNetwork,
		Blockchain: polygon.Blockchain,
	}
	chainID    = uint64(80001)
	chainIDHex = hexutil.EncodeUint64(chainID)

	//// Transfer-related variables
	// This key is unsafe for use in prod :)
	transferAddress = constructionAddress{
		privateKey:          "00fe21cc72608106f87959c32c27debbbc31ad9a45e8f50021cfdf0c3d8acb1d",
		compressedPublicKey: "03df5c7854e2264f641773f12fa3ce186ef1ebb294a7842ae7f3ef46ba502f7bff",
		publicKey:           "df5c7854e2264f641773f12fa3ce186ef1ebb294a7842ae7f3ef46ba502f7bffc990442f989d091ddaac352651de2d6f20fa0e65cc32d5283777177a41f51b7d",
		address:             "0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1",
	}

	constructionFromAddress = transferAddress.address
	constructionToAddress   = "0x3Fa177c2E87Cb24148EC403921dB577d140CC07c"

	transferValue            = uint64(20211004)
	transferValueHex         = hexutil.EncodeUint64(transferValue) // 0x134653C
	transferGasLimit         = uint64(21000)
	transferGasLimitHex      = hexutil.EncodeUint64(transferGasLimit) // 0x5208
	transferGasLimitERC20    = uint64(65000)
	transferGasLimitERC20Hex = hexutil.EncodeUint64(transferGasLimitERC20) // 0xFDE8
	transferNonce            = uint64(67)
	transferNonceHex         = hexutil.EncodeUint64(transferNonce) // 0x43
	transferNonceHex2        = "0x22"
	transferData             = "0xa9059cbb000000000000000000000000efd3dc58d60af3295b92ecd484caeb3a2f30b3e7000000000000000000000000000000000000000000000000000000000134653c" //nolint

	// transferGasCap           = uint64(40000000000)                         // 40 gwei
	transferGasTip              = uint64(40000000000)                            // 40 gwei, accounts for floor
	transferGasTipMultiplied    = uint64(80000000000)                            // 80 gwei (multiplied)
	transferGasTipHex           = hexutil.EncodeUint64(transferGasTip)           // 0x9502F9000
	transferGasTipMultipliedHex = hexutil.EncodeUint64(transferGasTipMultiplied) // 0x12A05F2000
	transferGasTipEstimate      = uint64(3000000000)                             // 3 gwei
	transferGasCapWithTip       = transferGasTipMultiplied + baseFeeMultiplied   // 80000000016 wei
	transferGasCapWithTipHex    = hexutil.EncodeUint64(transferGasCapWithTip)    // 0x12a05f2010
	minGasCap                   = big.NewInt(40000000000)                        // 40 gwei
	baseFee                     = uint64(8)                                      // 8 wei (testnet)
	baseFeeMultiplied           = uint64(16)                                     // 16 wei (testnet)

	header = EthTypes.Header{
		ParentHash:  common.Hash{},
		UncleHash:   common.Hash{},
		Coinbase:    common.Address{},
		Root:        common.Hash{},
		TxHash:      common.Hash{},
		ReceiptHash: common.Hash{},
		Bloom:       EthTypes.Bloom{},
		Difficulty:  nil,
		Number:      nil,
		GasLimit:    0,
		GasUsed:     0,
		Time:        0,
		Extra:       hexutil.Bytes{},
		BaseFee:     big.NewInt(int64(baseFee)),
	}
)

type constructionAddress struct {
	privateKey          string
	publicKey           string
	compressedPublicKey string
	address             string
}

func forceHexDecode(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("could not decode hex %s", s)
	}

	return b
}

func forceMarshalMap(t *testing.T, i interface{}) map[string]interface{} {
	m, err := marshalJSONMap(i)
	if err != nil {
		t.Fatalf("could not marshal map %s", types.PrintStruct(i))
	}

	return m
}

func TestConstructionFlowWithPendingNonce(t *testing.T) {
	tipMultiplier = 2.0
	cfg := &configuration.Configuration{
		Mode:    configuration.Online,
		Network: networkIdentifier,
		Params:  params.GoerliChainConfig,
	}
	cfg.Params.ChainID.SetString(configuration.MumbaiChainID, 10)

	mockClient := &mocks.Client{}
	servicer := NewAPIService(cfg, mockClient)
	ctx := context.Background()

	// Test Derive
	publicKey := &types.PublicKey{
		Bytes: forceHexDecode(
			t,
			transferAddress.compressedPublicKey,
		),
		CurveType: types.Secp256k1,
	}
	deriveResponse, err := servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
		NetworkIdentifier: networkIdentifier,
		PublicKey:         publicKey,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionDeriveResponse{
		AccountIdentifier: &types.AccountIdentifier{
			Address: transferAddress.address,
		},
	}, deriveResponse)

	// Test Preprocess
	intent := `[{"operation_identifier":{"index":0},"type":"CALL","account":{"address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1"},"amount":{"value":"-1000","currency":{"symbol":"MATIC","decimals":18}}},{"operation_identifier":{"index":1},"related_operations":[{"index":0}],"type":"CALL","account":{"address":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c"},"amount":{"value":"1000","currency":{"symbol":"MATIC","decimals":18}}}]`
	var ops []*types.Operation
	assert.NoError(t, json.Unmarshal([]byte(intent), &ops))
	preprocessResponse, err := servicer.ConstructionPreprocess(
		ctx,
		&types.ConstructionPreprocessRequest{
			NetworkIdentifier: networkIdentifier,
			Operations:        ops,
		},
	)
	assert.Nil(t, err)
	optionsRaw := `{"from":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1","to":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c","value":"0x3e8"}`
	var options options
	assert.NoError(t, json.Unmarshal([]byte(optionsRaw), &options))
	assert.Equal(t, &types.ConstructionPreprocessResponse{
		Options: forceMarshalMap(t, &options),
	}, preprocessResponse)

	// Test Metadata
	metadata1 := &metadata{
		GasLimit: 21000,
		GasTip:   big.NewInt(int64(transferGasTipMultiplied)),
		GasCap:   big.NewInt(int64(transferGasCapWithTip)),
		Nonce:    0,
		To:       constructionToAddress,
		Value:    big.NewInt(1000),
	}

	var blockNum *big.Int = nil
	mockClient.On(
		"BlockHeader",
		ctx,
		blockNum,
	).Return(
		&header,
		nil,
	).Once()
	mockClient.On(
		"SuggestGasTipCap",
		ctx,
	).Return(
		big.NewInt(int64(transferGasTipEstimate)), // this value is to be overriden by the 40 gwei min
		nil,
	).Once()
	mockClient.On(
		"PendingNonceAt",
		ctx,
		common.HexToAddress(constructionFromAddress),
	).Return(
		uint64(0),
		nil,
	).Once()
	metadataResponse, err := servicer.ConstructionMetadata(ctx, &types.ConstructionMetadataRequest{
		NetworkIdentifier: networkIdentifier,
		Options:           forceMarshalMap(t, &options),
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionMetadataResponse{
		Metadata: forceMarshalMap(t, metadata1),
		SuggestedFee: []*types.Amount{
			{
				Value:    "1680000000336000",
				Currency: polygon.Currency,
			},
		},
	}, metadataResponse)

	// Test Payloads
	unsignedRaw := `{"from":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1","to":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c","value":"0x3e8","data":"0x","nonce":"0x0","max_fee_per_gas":"0x12a05f2010","max_priority_fee_per_gas":"0x12a05f2000","gas":"0x5208","chain_id":"0x13881"}`
	payloadsResponse, err := servicer.ConstructionPayloads(ctx, &types.ConstructionPayloadsRequest{
		NetworkIdentifier: networkIdentifier,
		Operations:        ops,
		Metadata:          forceMarshalMap(t, metadata1),
	})
	assert.Nil(t, err)

	payloadsRaw := `[{"address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1","hex_bytes":"3c963a562c93b605123937ec8139694ea5cdfd66e51e770c2614f8698a4c3e04","account_identifier":{"address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1"},"signature_type":"ecdsa_recovery"}]`
	var payloads []*types.SigningPayload
	assert.NoError(t, json.Unmarshal([]byte(payloadsRaw), &payloads))
	// Printing the below can help debug
	// fmt.Printf("raw payloads: %x\n", payloads[0].Bytes)
	// fmt.Printf("raw payloads response: %x\n", payloadsResponse.Payloads[0].Bytes)
	assert.Equal(t, &types.ConstructionPayloadsResponse{
		UnsignedTransaction: unsignedRaw,
		Payloads:            payloads,
	}, payloadsResponse)

	// Test Parse Unsigned
	parseOpsRaw := `[{"operation_identifier":{"index":0},"type":"CALL","account":{"address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1"},"amount":{"value":"-1000","currency":{"symbol":"MATIC","decimals":18}}},{"operation_identifier":{"index":1},"related_operations":[{"index":0}],"type":"CALL","account":{"address":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c"},"amount":{"value":"1000","currency":{"symbol":"MATIC","decimals":18}}}]`
	var parseOps []*types.Operation
	assert.NoError(t, json.Unmarshal([]byte(parseOpsRaw), &parseOps))
	parseUnsignedResponse, err := servicer.ConstructionParse(ctx, &types.ConstructionParseRequest{
		NetworkIdentifier: networkIdentifier,
		Signed:            false,
		Transaction:       unsignedRaw,
	})
	assert.Nil(t, err)
	parseMetadata := &parseMetadata{
		Nonce:    metadata1.Nonce,
		GasCap:   metadata1.GasCap,
		GasTip:   metadata1.GasTip,
		GasLimit: metadata1.GasLimit,
		ChainID:  big.NewInt(80001),
	}
	assert.Equal(t, &types.ConstructionParseResponse{
		Operations:               parseOps,
		AccountIdentifierSigners: []*types.AccountIdentifier{},
		Metadata:                 forceMarshalMap(t, parseMetadata),
	}, parseUnsignedResponse)

	// Test Combine
	signaturesRaw := `[{"hex_bytes":"04e9edfd8d69c582e5360730f8abab546648146726de966ef5a004541715ccc05e006801d63c1a32a626b56ec77ac18ccefce1a17a93defd09c3613b17f604dd00","public_key":{"hex_bytes":"df5c7854e2264f641773f12fa3ce186ef1ebb294a7842ae7f3ef46ba502f7bffc990442f989d091ddaac352651de2d6f20fa0e65cc32d5283777177a41f51b7d","curve_type":"secp256k1"},"signing_payload":{"hex_bytes":"3c963a562c93b605123937ec8139694ea5cdfd66e51e770c2614f8698a4c3e04","address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1"},"signature_type":"ecdsa_recovery"}]`
	var signatures []*types.Signature
	assert.NoError(t, json.Unmarshal([]byte(signaturesRaw), &signatures))
	signedRaw := `{"type":"0x2","nonce":"0x0","gasPrice":null,"maxPriorityFeePerGas":"0x12a05f2000","maxFeePerGas":"0x12a05f2010","gas":"0x5208","value":"0x3e8","input":"0x","v":"0x0","r":"0x4e9edfd8d69c582e5360730f8abab546648146726de966ef5a004541715ccc0","s":"0x5e006801d63c1a32a626b56ec77ac18ccefce1a17a93defd09c3613b17f604dd","to":"0x3fa177c2e87cb24148ec403921db577d140cc07c","chainId":"0x13881","accessList":[],"hash":"0x286dd93132bb25afa11401968dd2393109a7023bc283f341f4986128383ed919"}` //nolint
	combineResponse, err := servicer.ConstructionCombine(ctx, &types.ConstructionCombineRequest{
		NetworkIdentifier:   networkIdentifier,
		UnsignedTransaction: unsignedRaw,
		Signatures:          signatures,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionCombineResponse{
		SignedTransaction: signedRaw,
	}, combineResponse)

	// Test Parse Signed
	var parseSignedOps []*types.Operation
	assert.NoError(t, json.Unmarshal([]byte(parseOpsRaw), &parseSignedOps))

	parseSignedResponse, err := servicer.ConstructionParse(ctx, &types.ConstructionParseRequest{
		NetworkIdentifier: networkIdentifier,
		Signed:            true,
		Transaction:       signedRaw,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionParseResponse{
		Operations: parseSignedOps,
		AccountIdentifierSigners: []*types.AccountIdentifier{
			{Address: constructionFromAddress},
		},
		Metadata: forceMarshalMap(t, parseMetadata),
	}, parseSignedResponse)

	// Test Hash
	transactionIdentifier := &types.TransactionIdentifier{
		Hash: "0x286dd93132bb25afa11401968dd2393109a7023bc283f341f4986128383ed919",
	}
	hashResponse, err := servicer.ConstructionHash(ctx, &types.ConstructionHashRequest{
		NetworkIdentifier: networkIdentifier,
		SignedTransaction: signedRaw,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.TransactionIdentifierResponse{
		TransactionIdentifier: transactionIdentifier,
	}, hashResponse)

	// Test Submit
	mockClient.On(
		"SendTransaction",
		ctx,
		mock.Anything, // can't test ethTx here because it contains "time"
	).Return(
		nil,
	)
	submitResponse, err := servicer.ConstructionSubmit(ctx, &types.ConstructionSubmitRequest{
		NetworkIdentifier: networkIdentifier,
		SignedTransaction: signedRaw,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.TransactionIdentifierResponse{
		TransactionIdentifier: transactionIdentifier,
	}, submitResponse)

	mockClient.AssertExpectations(t)

	// Test with 1.0 gas tip multiplier
	tipMultiplier = 1.0
	mockClient.
		On("BlockHeader", ctx, blockNum).
		Return(&header, nil).
		Once()
	mockClient.
		On("SuggestGasTipCap", ctx).
		Return(big.NewInt(int64(transferGasTipEstimate)), nil).
		Once()
	mockClient.
		On("PendingNonceAt", ctx, common.HexToAddress(constructionFromAddress)).
		Return(uint64(0), nil).
		Once()

	gasTipBigInt := big.NewInt(int64(transferGasTip))
	metadata2 := &metadata{
		GasLimit: 21000,
		GasTip:   gasTipBigInt,                                                         // 40 gwei, no multiplier
		GasCap:   new(big.Int).Add(gasTipBigInt, big.NewInt(int64(baseFeeMultiplied))), // gasTip + baseFee*2 = 80 + 60 = 140gwei
		Nonce:    0,
		To:       constructionToAddress,
		Value:    big.NewInt(1000),
	}

	metadataResponse, err = servicer.ConstructionMetadata(ctx, &types.ConstructionMetadataRequest{
		NetworkIdentifier: networkIdentifier,
		Options:           forceMarshalMap(t, &options),
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionMetadataResponse{
		Metadata: forceMarshalMap(t, metadata2),
		SuggestedFee: []*types.Amount{
			{
				Value:    "840000000336000", // gasCap * 21000
				Currency: polygon.Currency,
			},
		},
	}, metadataResponse)
}

func TestConstructionFlowWithInputNonce(t *testing.T) {
	tipMultiplier = 2.0
	networkIdentifier = &types.NetworkIdentifier{
		Network:    polygon.TestnetNetwork,
		Blockchain: polygon.Blockchain,
	}

	cfg := &configuration.Configuration{
		Mode:    configuration.Online,
		Network: networkIdentifier,
		Params:  params.GoerliChainConfig,
	}
	cfg.Params.ChainID.SetString(configuration.MumbaiChainID, 10)

	mockClient := &mocks.Client{}
	servicer := NewAPIService(cfg, mockClient)
	ctx := context.Background()

	// Test Derive
	publicKey := &types.PublicKey{
		Bytes: forceHexDecode(
			t,
			transferAddress.compressedPublicKey,
		),
		CurveType: types.Secp256k1,
	}
	deriveResponse, err := servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
		NetworkIdentifier: networkIdentifier,
		PublicKey:         publicKey,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionDeriveResponse{
		AccountIdentifier: &types.AccountIdentifier{
			Address: transferAddress.address,
		},
	}, deriveResponse)

	// Test Preprocess
	intent := `[{"operation_identifier":{"index":0},"type":"CALL","account":{"address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1"},"amount":{"value":"-1000","currency":{"symbol":"MATIC","decimals":18}}},{"operation_identifier":{"index":1},"related_operations":[{"index":0}],"type":"CALL","account":{"address":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c"},"amount":{"value":"1000","currency":{"symbol":"MATIC","decimals":18}}}]`
	var ops []*types.Operation
	assert.NoError(t, json.Unmarshal([]byte(intent), &ops))
	preprocessResponse, err := servicer.ConstructionPreprocess(
		ctx,
		&types.ConstructionPreprocessRequest{
			NetworkIdentifier: networkIdentifier,
			Operations:        ops,
			Metadata:          map[string]interface{}{"nonce": "1"},
		},
	)
	assert.Nil(t, err)
	optionsRaw := `{"from":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1","nonce":"0x1","to":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c","value":"0x3e8"}`
	var options options
	assert.NoError(t, json.Unmarshal([]byte(optionsRaw), &options))
	assert.Equal(t, &types.ConstructionPreprocessResponse{
		Options: forceMarshalMap(t, &options),
	}, preprocessResponse)

	// Test Metadata
	metadata := &metadata{
		GasLimit: 21000,
		GasTip:   big.NewInt(int64(transferGasTipMultiplied)),
		GasCap:   big.NewInt(int64(transferGasCapWithTip)),
		Nonce:    1,
		To:       constructionToAddress,
		Value:    big.NewInt(1000),
	}

	var blockNum *big.Int = nil

	mockClient.On(
		"BlockHeader",
		ctx,
		blockNum,
	).Return(
		&header,
		nil,
	).Once()
	mockClient.On(
		"SuggestGasTipCap",
		ctx,
	).Return(
		big.NewInt(int64(transferGasTipEstimate)),
		nil,
	).Once()
	metadataResponse, err := servicer.ConstructionMetadata(ctx, &types.ConstructionMetadataRequest{
		NetworkIdentifier: networkIdentifier,
		Options:           preprocessResponse.Options,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionMetadataResponse{
		Metadata: forceMarshalMap(t, metadata),
		SuggestedFee: []*types.Amount{
			{
				Value:    "1680000000336000",
				Currency: polygon.Currency,
			},
		},
	}, metadataResponse)

	// Test Payloads
	unsignedRaw := `{"from":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1","to":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c","value":"0x3e8","data":"0x","nonce":"0x1","max_fee_per_gas":"0x12a05f2010","max_priority_fee_per_gas":"0x12a05f2000","gas":"0x5208","chain_id":"0x13881"}`
	payloadsResponse, err := servicer.ConstructionPayloads(ctx, &types.ConstructionPayloadsRequest{
		NetworkIdentifier: networkIdentifier,
		Operations:        ops,
		Metadata:          forceMarshalMap(t, metadata),
	})
	assert.Nil(t, err)
	payloadsRaw := `[{"address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1","hex_bytes":"2153388fbad156e699e9bb8373ec7003c27d5ad5b71a90a7532f9ec25ea63c34","account_identifier":{"address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1"},"signature_type":"ecdsa_recovery"}]`
	var payloads []*types.SigningPayload
	assert.NoError(t, json.Unmarshal([]byte(payloadsRaw), &payloads))
	assert.Equal(t, &types.ConstructionPayloadsResponse{
		UnsignedTransaction: unsignedRaw,
		Payloads:            payloads,
	}, payloadsResponse)

	// Test Parse Unsigned
	parseOpsRaw := `[{"operation_identifier":{"index":0},"type":"CALL","account":{"address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1"},"amount":{"value":"-1000","currency":{"symbol":"MATIC","decimals":18}}},{"operation_identifier":{"index":1},"related_operations":[{"index":0}],"type":"CALL","account":{"address":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c"},"amount":{"value":"1000","currency":{"symbol":"MATIC","decimals":18}}}]`
	var parseOps []*types.Operation
	assert.NoError(t, json.Unmarshal([]byte(parseOpsRaw), &parseOps))
	parseUnsignedResponse, err := servicer.ConstructionParse(ctx, &types.ConstructionParseRequest{
		NetworkIdentifier: networkIdentifier,
		Signed:            false,
		Transaction:       unsignedRaw,
	})
	assert.Nil(t, err)
	parseMetadata := &parseMetadata{
		Nonce:    metadata.Nonce,
		GasLimit: metadata.GasLimit,
		GasCap:   metadata.GasCap,
		GasTip:   metadata.GasTip,
		ChainID:  big.NewInt(80001),
	}
	assert.Equal(t, &types.ConstructionParseResponse{
		Operations:               parseOps,
		AccountIdentifierSigners: []*types.AccountIdentifier{},
		Metadata:                 forceMarshalMap(t, parseMetadata),
	}, parseUnsignedResponse)

	// Test Combine
	signaturesRaw := `[{"hex_bytes":"78d6a8a6b7316178f1362dd3434ef1ef8b9b071d65bca3293c5666766474d41a7bfc320189e340dd6b1fd5545820dd53b7c8b33994005cd28620389fad21eb1600","public_key":{"hex_bytes":"df5c7854e2264f641773f12fa3ce186ef1ebb294a7842ae7f3ef46ba502f7bffc990442f989d091ddaac352651de2d6f20fa0e65cc32d5283777177a41f51b7d","curve_type":"secp256k1"},"signing_payload":{"hex_bytes":"2153388fbad156e699e9bb8373ec7003c27d5ad5b71a90a7532f9ec25ea63c34","address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1"},"signature_type":"ecdsa_recovery"}]`
	var signatures []*types.Signature
	assert.NoError(t, json.Unmarshal([]byte(signaturesRaw), &signatures))
	signedRaw := `{"type":"0x2","nonce":"0x1","gasPrice":null,"maxPriorityFeePerGas":"0x12a05f2000","maxFeePerGas":"0x12a05f2010","gas":"0x5208","value":"0x3e8","input":"0x","v":"0x0","r":"0x78d6a8a6b7316178f1362dd3434ef1ef8b9b071d65bca3293c5666766474d41a","s":"0x7bfc320189e340dd6b1fd5545820dd53b7c8b33994005cd28620389fad21eb16","to":"0x3fa177c2e87cb24148ec403921db577d140cc07c","chainId":"0x13881","accessList":[],"hash":"0xd398aaa07b3daa87b894e35fc4305ded464b34418a73cb9143c1f905088a609f"}` // nolint
	combineResponse, err := servicer.ConstructionCombine(ctx, &types.ConstructionCombineRequest{
		NetworkIdentifier:   networkIdentifier,
		UnsignedTransaction: unsignedRaw,
		Signatures:          signatures,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionCombineResponse{
		SignedTransaction: signedRaw,
	}, combineResponse)

	// Test Parse Signed
	var parseSignedOps []*types.Operation
	assert.NoError(t, json.Unmarshal([]byte(parseOpsRaw), &parseSignedOps))
	parseSignedResponse, err := servicer.ConstructionParse(ctx, &types.ConstructionParseRequest{
		NetworkIdentifier: networkIdentifier,
		Signed:            true,
		Transaction:       signedRaw,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionParseResponse{
		Operations: parseSignedOps,
		AccountIdentifierSigners: []*types.AccountIdentifier{
			{Address: constructionFromAddress},
		},
		Metadata: forceMarshalMap(t, parseMetadata),
	}, parseSignedResponse)

	// Test Hash
	transactionIdentifier := &types.TransactionIdentifier{
		Hash: "0xd398aaa07b3daa87b894e35fc4305ded464b34418a73cb9143c1f905088a609f",
	}
	hashResponse, err := servicer.ConstructionHash(ctx, &types.ConstructionHashRequest{
		NetworkIdentifier: networkIdentifier,
		SignedTransaction: signedRaw,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.TransactionIdentifierResponse{
		TransactionIdentifier: transactionIdentifier,
	}, hashResponse)

	// Test Submit
	mockClient.On(
		"SendTransaction",
		ctx,
		mock.Anything, // can't test ethTx here because it contains "time"
	).Return(
		nil,
	)
	submitResponse, err := servicer.ConstructionSubmit(ctx, &types.ConstructionSubmitRequest{
		NetworkIdentifier: networkIdentifier,
		SignedTransaction: signedRaw,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.TransactionIdentifierResponse{
		TransactionIdentifier: transactionIdentifier,
	}, submitResponse)

	mockClient.AssertExpectations(t)
}

func TestConstructionFlowWithInputNonceAndGasTip(t *testing.T) {
	/** Leaving useful reference variables here commented in order to avoid compiler complaints */

	// overriddenTransferGasTip              := uint64(123000000000)                            // 123 gwei, overridden
	overriddenTransferGasTipMultiplied    := uint64(246000000000)                            // 246 gwei (multiplied)
	// overriddenTransferGasTipHex           := hexutil.EncodeUint64(overriddenTransferGasTip)           // 0x1ca35f0e00
	// overriddenTransferGasTipMultipliedHex := hexutil.EncodeUint64(overriddenTransferGasTipMultiplied) // 0x3946be1c00
	overriddenTransferGasTipEstimate      := uint64(3000000000)                             // 3 gwei
	overriddenTransferGasCapWithTip       := overriddenTransferGasTipMultiplied + baseFeeMultiplied   // 246 gwei + 16 wei == 246000000016
	// overriddenTransferGasCapWithTipHex    := hexutil.EncodeUint64(overriddenTransferGasCapWithTip)    // 0x3946be1c10

	tipMultiplier = 2.0
	networkIdentifier = &types.NetworkIdentifier{
		Network:    polygon.TestnetNetwork,
		Blockchain: polygon.Blockchain,
	}

	cfg := &configuration.Configuration{
		Mode:    configuration.Online,
		Network: networkIdentifier,
		Params:  params.GoerliChainConfig,
	}
	cfg.Params.ChainID.SetString(configuration.MumbaiChainID, 10)

	mockClient := &mocks.Client{}
	servicer := NewAPIService(cfg, mockClient)
	ctx := context.Background()

	// Test Derive
	publicKey := &types.PublicKey{
		Bytes: forceHexDecode(
			t,
			transferAddress.compressedPublicKey,
		),
		CurveType: types.Secp256k1,
	}
	deriveResponse, err := servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
		NetworkIdentifier: networkIdentifier,
		PublicKey:         publicKey,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionDeriveResponse{
		AccountIdentifier: &types.AccountIdentifier{
			Address: transferAddress.address,
		},
	}, deriveResponse)

	// Test Preprocess
	intent := `[{"operation_identifier":{"index":0},"type":"CALL","account":{"address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1"},"amount":{"value":"-1000","currency":{"symbol":"MATIC","decimals":18}}},{"operation_identifier":{"index":1},"related_operations":[{"index":0}],"type":"CALL","account":{"address":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c"},"amount":{"value":"1000","currency":{"symbol":"MATIC","decimals":18}}}]`
	var ops []*types.Operation
	assert.NoError(t, json.Unmarshal([]byte(intent), &ops))
	preprocessResponse, err := servicer.ConstructionPreprocess(
		ctx,
		&types.ConstructionPreprocessRequest{
			NetworkIdentifier: networkIdentifier,
			Operations:        ops,
			Metadata:          map[string]interface{}{"nonce": "1","gas_tip": "123000000000"},
		},
	)
	assert.Nil(t, err)
	optionsRaw := `{"from":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1","nonce":"0x1","to":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c","value":"0x3e8","gas_tip":"0x1ca35f0e00"}`
	var options options
	assert.NoError(t, json.Unmarshal([]byte(optionsRaw), &options))
	assert.Equal(t, &types.ConstructionPreprocessResponse{
		Options: forceMarshalMap(t, &options),
	}, preprocessResponse)

	// Test Metadata
	metadata := &metadata{
		GasLimit: 21000,
		GasTip:   big.NewInt(int64(overriddenTransferGasTipMultiplied)),
		GasCap:   big.NewInt(int64(overriddenTransferGasCapWithTip)),
		Nonce:    1,
		To:       constructionToAddress,
		Value:    big.NewInt(1000),
	}

	var blockNum *big.Int = nil

	mockClient.On(
		"BlockHeader",
		ctx,
		blockNum,
	).Return(
		&header,
		nil,
	).Once()
	mockClient.On(
		"SuggestGasTipCap",
		ctx,
	).Return(
		big.NewInt(int64(overriddenTransferGasTipEstimate)),
		nil,
	).Once()
	metadataResponse, err := servicer.ConstructionMetadata(ctx, &types.ConstructionMetadataRequest{
		NetworkIdentifier: networkIdentifier,
		Options:           preprocessResponse.Options,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionMetadataResponse{
		Metadata: forceMarshalMap(t, metadata),
		SuggestedFee: []*types.Amount{
			{
				Value:    "5166000000336000",
				Currency: polygon.Currency,
			},
		},
	}, metadataResponse)

	// Test Payloads
	unsignedRaw := `{"from":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1","to":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c","value":"0x3e8","data":"0x","nonce":"0x1","max_fee_per_gas":"0x3946be1c10","max_priority_fee_per_gas":"0x3946be1c00","gas":"0x5208","chain_id":"0x13881"}`
	payloadsResponse, err := servicer.ConstructionPayloads(ctx, &types.ConstructionPayloadsRequest{
		NetworkIdentifier: networkIdentifier,
		Operations:        ops,
		Metadata:          forceMarshalMap(t, metadata),
	})
	assert.Nil(t, err)
	payloadsRaw := `[{"address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1","hex_bytes":"813f93a233d21e454bde73920eeedd0ecffdda5c1792635c50810f9b4c15cbca","account_identifier":{"address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1"},"signature_type":"ecdsa_recovery"}]`
	var payloads []*types.SigningPayload
	assert.NoError(t, json.Unmarshal([]byte(payloadsRaw), &payloads))
	assert.Equal(t, &types.ConstructionPayloadsResponse{
		UnsignedTransaction: unsignedRaw,
		Payloads:            payloads,
	}, payloadsResponse)

	// Test Parse Unsigned
	parseOpsRaw := `[{"operation_identifier":{"index":0},"type":"CALL","account":{"address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1"},"amount":{"value":"-1000","currency":{"symbol":"MATIC","decimals":18}}},{"operation_identifier":{"index":1},"related_operations":[{"index":0}],"type":"CALL","account":{"address":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c"},"amount":{"value":"1000","currency":{"symbol":"MATIC","decimals":18}}}]`
	var parseOps []*types.Operation
	assert.NoError(t, json.Unmarshal([]byte(parseOpsRaw), &parseOps))
	parseUnsignedResponse, err := servicer.ConstructionParse(ctx, &types.ConstructionParseRequest{
		NetworkIdentifier: networkIdentifier,
		Signed:            false,
		Transaction:       unsignedRaw,
	})
	assert.Nil(t, err)
	parseMetadata := &parseMetadata{
		Nonce:    metadata.Nonce,
		GasLimit: metadata.GasLimit,
		GasCap:   metadata.GasCap,
		GasTip:   metadata.GasTip,
		ChainID:  big.NewInt(80001),
	}
	assert.Equal(t, &types.ConstructionParseResponse{
		Operations:               parseOps,
		AccountIdentifierSigners: []*types.AccountIdentifier{},
		Metadata:                 forceMarshalMap(t, parseMetadata),
	}, parseUnsignedResponse)

	// Test Combine
	signaturesRaw := `[{"hex_bytes":"ae4c4901ffa532ed1c73688d3b2af602fbba6f1484cbd5ed2cb9cd0aeac1935a152a40d9fab96a9e7c2f9969862fb6a9fbfbd5c68cb1d044b37e61e635fc4a7901","public_key":{"hex_bytes":"df5c7854e2264f641773f12fa3ce186ef1ebb294a7842ae7f3ef46ba502f7bffc990442f989d091ddaac352651de2d6f20fa0e65cc32d5283777177a41f51b7d","curve_type":"secp256k1"},"signing_payload":{"hex_bytes":"813f93a233d21e454bde73920eeedd0ecffdda5c1792635c50810f9b4c15cbca","address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1"},"signature_type":"ecdsa_recovery"}]`
	var signatures []*types.Signature
	assert.NoError(t, json.Unmarshal([]byte(signaturesRaw), &signatures))
	signedRaw := `{"type":"0x2","nonce":"0x1","gasPrice":null,"maxPriorityFeePerGas":"0x3946be1c00","maxFeePerGas":"0x3946be1c10","gas":"0x5208","value":"0x3e8","input":"0x","v":"0x1","r":"0xae4c4901ffa532ed1c73688d3b2af602fbba6f1484cbd5ed2cb9cd0aeac1935a","s":"0x152a40d9fab96a9e7c2f9969862fb6a9fbfbd5c68cb1d044b37e61e635fc4a79","to":"0x3fa177c2e87cb24148ec403921db577d140cc07c","chainId":"0x13881","accessList":[],"hash":"0x46ccfdf9713c2110ae5e34449b4682e922706f345a61827a7de13c67957f43d1"}` // nolint
	combineResponse, err := servicer.ConstructionCombine(ctx, &types.ConstructionCombineRequest{
		NetworkIdentifier:   networkIdentifier,
		UnsignedTransaction: unsignedRaw,
		Signatures:          signatures,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionCombineResponse{
		SignedTransaction: signedRaw,
	}, combineResponse)

	// Test Parse Signed
	var parseSignedOps []*types.Operation
	assert.NoError(t, json.Unmarshal([]byte(parseOpsRaw), &parseSignedOps))
	parseSignedResponse, err := servicer.ConstructionParse(ctx, &types.ConstructionParseRequest{
		NetworkIdentifier: networkIdentifier,
		Signed:            true,
		Transaction:       signedRaw,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionParseResponse{
		Operations: parseSignedOps,
		AccountIdentifierSigners: []*types.AccountIdentifier{
			{Address: constructionFromAddress},
		},
		Metadata: forceMarshalMap(t, parseMetadata),
	}, parseSignedResponse)

	// Test Hash
	transactionIdentifier := &types.TransactionIdentifier{
		Hash: "0x46ccfdf9713c2110ae5e34449b4682e922706f345a61827a7de13c67957f43d1",
	}
	hashResponse, err := servicer.ConstructionHash(ctx, &types.ConstructionHashRequest{
		NetworkIdentifier: networkIdentifier,
		SignedTransaction: signedRaw,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.TransactionIdentifierResponse{
		TransactionIdentifier: transactionIdentifier,
	}, hashResponse)

	// Test Submit
	mockClient.On(
		"SendTransaction",
		ctx,
		mock.Anything, // can't test ethTx here because it contains "time"
	).Return(
		nil,
	)
	submitResponse, err := servicer.ConstructionSubmit(ctx, &types.ConstructionSubmitRequest{
		NetworkIdentifier: networkIdentifier,
		SignedTransaction: signedRaw,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.TransactionIdentifierResponse{
		TransactionIdentifier: transactionIdentifier,
	}, submitResponse)

	mockClient.AssertExpectations(t)
}

func templateError(error *types.Error, context string) *types.Error {
	return &types.Error{
		Code:      error.Code,
		Message:   error.Message,
		Retriable: false,
		Details: map[string]interface{}{
			"context": context,
		},
	}
}

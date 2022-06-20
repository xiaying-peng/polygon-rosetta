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

	"github.com/maticnetwork/polygon-rosetta/configuration"
	mocks "github.com/maticnetwork/polygon-rosetta/mocks/services"
	"github.com/maticnetwork/polygon-rosetta/polygon"

	"github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var (
	networkIdentifier = &types.NetworkIdentifier{
		Network:    polygon.TestnetNetwork,
		Blockchain: polygon.Blockchain,
	}

	chainID    = uint64(80001)
	chainIDHex = hexutil.EncodeUint64(chainID)

	fromAddress          = "0x966fbC4E1F3a938Cf7798695C3244d9C7C190015"
	toAddress            = "0xefD3dc58D60aF3295B92ecd484CAEB3A2f30b3e7"
	tokenContractAddress = "0x2d7882beDcbfDDce29Ba99965dd3cdF7fcB10A1e"

	// key is unsafe for use in prod :)
	transferAddress = constructionAddress{
		privateKey:          "00fe21cc72608106f87959c32c27debbbc31ad9a45e8f50021cfdf0c3d8acb1d",
		compressedPublicKey: "03df5c7854e2264f641773f12fa3ce186ef1ebb294a7842ae7f3ef46ba502f7bff",
		publicKey:           "df5c7854e2264f641773f12fa3ce186ef1ebb294a7842ae7f3ef46ba502f7bffc990442f989d091ddaac352651de2d6f20fa0e65cc32d5283777177a41f51b7d",
		address:             "0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1",
	}

	constructionFromAddress = transferAddress.address
	constructionToAddress   = "0x3Fa177c2E87Cb24148EC403921dB577d140CC07c"

	transferValue         = uint64(20211004)
	transferGasLimit      = uint64(21000)
	transferGasLimitERC20 = uint64(65000)
	transferNonce         = uint64(67)
	transferData          = "0xa9059cbb000000000000000000000000efd3dc58d60af3295b92ecd484caeb3a2f30b3e7000000000000000000000000000000000000000000000000000000000134653c" //nolint
	transferGasCap        = uint64(60000000000) // 60 gwei
	transferGasTip        = uint64(1500000000) // 1.5 gwei
	transferGasCapWithTip = transferGasCap + transferGasTip // 61.5 gwei

	transferValueHex         = hexutil.EncodeUint64(transferValue) // 0x134653C
	transferGasLimitHex      = hexutil.EncodeUint64(transferGasLimit) // 0x5208
	transferGasLimitERC20Hex = hexutil.EncodeUint64(transferGasLimitERC20) // 0xFDE8
	transferNonceHex         = hexutil.EncodeUint64(transferNonce)
	transferNonceHex2        = "0x22"
	transferGasCapHex        = hexutil.EncodeUint64(transferGasCap) // 0xdf8475800
	transferGasTipHex        = hexutil.EncodeUint64(transferGasTip) // 0x59682F00
	transferGasCapWithTipHex = hexutil.EncodeUint64(transferGasCapWithTip) // 0xE51AF8700

	minGasCap    = big.NewInt(30000000000)
	minGasCapHex = hexutil.EncodeUint64(minGasCap.Uint64())

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
		BaseFee:     minGasCap, // equivalent to 30 gwei, previously 500000
	}

	headerWithLowBaseFee = EthTypes.Header{
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
		BaseFee:     big.NewInt(10000000000), // equivalent to 10 gwei
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
	metadata := &metadata{
		GasLimit: 21000,
		GasTip:   big.NewInt(int64(transferGasTip)),
		GasCap:   big.NewInt(int64(transferGasCapWithTip)), // math: gasCap = new(big.Int).Add(gasTip, new(big.Int).Mul(baseFee, multiplier))
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
		big.NewInt(int64(transferGasTip)),
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
		Metadata: forceMarshalMap(t, metadata),
		SuggestedFee: []*types.Amount{
			{
				Value:    "1291500000000000",
				Currency: polygon.Currency,
			},
		},
	}, metadataResponse)

	// Test Payloads
	unsignedRaw := `{"from":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1","to":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c","value":"0x3e8","data":"0x","nonce":"0x0","max_fee_per_gas":"0xe51af8700","max_priority_fee_per_gas":"0x59682f00","gas":"0x5208","chain_id":"0x13881"}`
	payloadsResponse, err := servicer.ConstructionPayloads(ctx, &types.ConstructionPayloadsRequest{
		NetworkIdentifier: networkIdentifier,
		Operations:        ops,
		Metadata:          forceMarshalMap(t, metadata),
	})
	assert.Nil(t, err)

	payloadsRaw := `[{"address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1","hex_bytes":"0206e22e9bded068a76f89a86e0849b7e6ff8f6e8a22e1b679fd87a08635a9f2","account_identifier":{"address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1"},"signature_type":"ecdsa_recovery"}]`
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
		GasCap:   metadata.GasCap,
		GasTip:   metadata.GasTip,
		GasLimit: metadata.GasLimit,
		ChainID:  big.NewInt(80001),
	}
	assert.Equal(t, &types.ConstructionParseResponse{
		Operations:               parseOps,
		AccountIdentifierSigners: []*types.AccountIdentifier{},
		Metadata:                 forceMarshalMap(t, parseMetadata),
	}, parseUnsignedResponse)

	// Test Combine
	signaturesRaw := `[{"hex_bytes":"660e6778daed0d34f1c976057ee9742fef962fc67ceef2fd9e291f2558b4bc4d784b2bf12f723a1741fdf76f68dd4704f795d88ac6dc2de0d60892b0391c2d4800","public_key":{"hex_bytes":"df5c7854e2264f641773f12fa3ce186ef1ebb294a7842ae7f3ef46ba502f7bffc990442f989d091ddaac352651de2d6f20fa0e65cc32d5283777177a41f51b7d","curve_type":"secp256k1"},"signing_payload":{"hex_bytes":"0206e22e9bded068a76f89a86e0849b7e6ff8f6e8a22e1b679fd87a08635a9f2","address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1"},"signature_type":"ecdsa_recovery"}]`
	var signatures []*types.Signature
	assert.NoError(t, json.Unmarshal([]byte(signaturesRaw), &signatures))
	signedRaw := `{"type":"0x2","nonce":"0x0","gasPrice":null,"maxPriorityFeePerGas":"0x59682f00","maxFeePerGas":"0xe51af8700","gas":"0x5208","value":"0x3e8","input":"0x","v":"0x0","r":"0x660e6778daed0d34f1c976057ee9742fef962fc67ceef2fd9e291f2558b4bc4d","s":"0x784b2bf12f723a1741fdf76f68dd4704f795d88ac6dc2de0d60892b0391c2d48","to":"0x3fa177c2e87cb24148ec403921db577d140cc07c","chainId":"0x13881","accessList":[],"hash":"0x735e09de7e8b7b660b564068cb85275edcb5a432a07148100d85d05849b3013e"}` //nolint
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
		Hash: "0x735e09de7e8b7b660b564068cb85275edcb5a432a07148100d85d05849b3013e",
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

func TestConstructionFlowWithInputNonce(t *testing.T) {
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
		GasTip:   big.NewInt(int64(transferGasTip)),
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
		big.NewInt(1500000000),
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
				Value:    "1291500000000000",
				Currency: polygon.Currency,
			},
		},
	}, metadataResponse)

	// Test Payloads
	unsignedRaw := `{"from":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1","to":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c","value":"0x3e8","data":"0x","nonce":"0x1","max_fee_per_gas":"0xe51af8700","max_priority_fee_per_gas":"0x59682f00","gas":"0x5208","chain_id":"0x13881"}`
	payloadsResponse, err := servicer.ConstructionPayloads(ctx, &types.ConstructionPayloadsRequest{
		NetworkIdentifier: networkIdentifier,
		Operations:        ops,
		Metadata:          forceMarshalMap(t, metadata),
	})
	assert.Nil(t, err)
	payloadsRaw := `[{"address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1","hex_bytes":"886c43dac9ea8064a47b2c544617c20c8d2a0e67025d59b6970887ac6cb2f81b","account_identifier":{"address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1"},"signature_type":"ecdsa_recovery"}]`
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
	signaturesRaw := `[{"hex_bytes":"e8d0fd97f5f1ce5aaa0c4c2c02d0bb1c65a1a4baa2a970efdc85e77d54f117590d953748115c85ade80806a0e4c8a9365c37b984b0837ffddda4af3397e8090000","public_key":{"hex_bytes":"0405e82ac561143aafc13ba109677a597c8f797b07417d0addd7a346ad35882b3c4a006620e02127b9a32e90979ff93ecad0a2f577db238163a50023e393e354ff","curve_type":"secp256k1"},"signing_payload":{"hex_bytes":"2fbbd3c6a16a992785dbb6d6f3589d26dbc277aa83657b130b960c0da2422670","address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1"},"signature_type":"ecdsa_recovery"}]`
	var signatures []*types.Signature
	assert.NoError(t, json.Unmarshal([]byte(signaturesRaw), &signatures))
	signedRaw := `{"type":"0x2","nonce":"0x1","gasPrice":null,"maxPriorityFeePerGas":"0x59682f00","maxFeePerGas":"0xe51af8700","gas":"0x5208","value":"0x3e8","input":"0x","v":"0x0","r":"0xe8d0fd97f5f1ce5aaa0c4c2c02d0bb1c65a1a4baa2a970efdc85e77d54f11759","s":"0xd953748115c85ade80806a0e4c8a9365c37b984b0837ffddda4af3397e80900","to":"0x3fa177c2e87cb24148ec403921db577d140cc07c","chainId":"0x13881","accessList":[],"hash":"0x9c2c6b5e84514c1668ce5c4ae5fe169bb3662812c4042d1be5af00fb0a7168e5"}` // nolint
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
		Hash: "0x9c2c6b5e84514c1668ce5c4ae5fe169bb3662812c4042d1be5af00fb0a7168e5",
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

func templateOperations(amount uint64, currency *types.Currency) []*types.Operation {
	return rosettaOperations(
		fromAddress,
		toAddress,
		big.NewInt(int64(amount)),
		currency,
	)
}

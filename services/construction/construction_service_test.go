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
	"fmt"
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

	constructionFromAddress = "0x5aCB42b3cfCD734a57AFF800139ba1354b549159"
	constructionToAddress   = "0x3Fa177c2E87Cb24148EC403921dB577d140CC07c"

	transferValue         = uint64(20211004)
	transferGasLimit      = uint64(21000)
	transferGasLimitERC20 = uint64(65000)
	transferNonce         = uint64(67)
	transferData          = "0xa9059cbb000000000000000000000000efd3dc58d60af3295b92ecd484caeb3a2f30b3e7000000000000000000000000000000000000000000000000000000000134653c" //nolint
	transferGasCap        = uint64(60000000000) // 60 gwei
	transferGasTip        = uint64(1500000000) // 1.5 gwei
	transferGasCapWithTip = transferGasCap + transferGasTip

	transferValueHex         = hexutil.EncodeUint64(transferValue)
	transferGasLimitHex      = hexutil.EncodeUint64(transferGasLimit)
	transferGasLimitERC20Hex = hexutil.EncodeUint64(transferGasLimitERC20)
	transferNonceHex         = hexutil.EncodeUint64(transferNonce)
	transferNonceHex2        = "0x22"
	transferGasCapHex        = hexutil.EncodeUint64(transferGasCap)
	transferGasTipHex        = hexutil.EncodeUint64(transferGasTip)
	transferGasCapWithTipHex = hexutil.EncodeUint64(transferGasCapWithTip)

	minGasCap = big.NewInt(30000000000)
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
			"0212e9f98d9750e5f74b4b4b00df39074f86c79187943bdb3c5a9c89ffc1ed0188",
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
			Address: "0xD10a72Cf054650931365Cc44D912a4FD75257058",
		},
	}, deriveResponse)

	// Test Preprocess
	intent := `[{"operation_identifier":{"index":0},"type":"CALL","account":{"address":"0x5aCB42b3cfCD734a57AFF800139ba1354b549159"},"amount":{"value":"-1000","currency":{"symbol":"MATIC","decimals":18}}},{"operation_identifier":{"index":1},"related_operations":[{"index":0}],"type":"CALL","account":{"address":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c"},"amount":{"value":"1000","currency":{"symbol":"MATIC","decimals":18}}}]`
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
	optionsRaw := `{"from":"0x5aCB42b3cfCD734a57AFF800139ba1354b549159","to":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c","value":"0x3e8"}`
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
	unsignedRaw := `{"from":"0x5aCB42b3cfCD734a57AFF800139ba1354b549159","to":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c","value":"0x3e8","data":"0x","nonce":"0x0","max_fee_per_gas":"0xe51af8700","max_priority_fee_per_gas":"0x59682f00","gas":"0x5208","chain_id":"0x13881"}`
	payloadsResponse, err := servicer.ConstructionPayloads(ctx, &types.ConstructionPayloadsRequest{
		NetworkIdentifier: networkIdentifier,
		Operations:        ops,
		Metadata:          forceMarshalMap(t, metadata),
	})
	assert.Nil(t, err)

	payloadsRaw := `[{"address":"0x5aCB42b3cfCD734a57AFF800139ba1354b549159","hex_bytes":"0206e22e9bded068a76f89a86e0849b7e6ff8f6e8a22e1b679fd87a08635a9f2","account_identifier":{"address":"0x5aCB42b3cfCD734a57AFF800139ba1354b549159"},"signature_type":"ecdsa_recovery"}]`
	var payloads []*types.SigningPayload
	assert.NoError(t, json.Unmarshal([]byte(payloadsRaw), &payloads))

	hexString := hexutil.Encode(payloadsResponse.Payloads[0].Bytes)
	fmt.Printf("hexstring %s", hexString)
	assert.Equal(t, &types.ConstructionPayloadsResponse{
		UnsignedTransaction: unsignedRaw,
		Payloads:            payloads,
	}, payloadsResponse)

	// Test Parse Unsigned
	parseOpsRaw := `[{"operation_identifier":{"index":0},"type":"CALL","account":{"address":"0x5aCB42b3cfCD734a57AFF800139ba1354b549159"},"amount":{"value":"-1000","currency":{"symbol":"MATIC","decimals":18}}},{"operation_identifier":{"index":1},"related_operations":[{"index":0}],"type":"CALL","account":{"address":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c"},"amount":{"value":"1000","currency":{"symbol":"MATIC","decimals":18}}}]`
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
	signaturesRaw := `[{"hex_bytes":"9f2f61a9a90f6695b10ed04102dca3e0aa50a10263afd861761226e3e61903a62fb42a9e8d96af626e64fd20573338f41d4f90ea9834ce6aa4ff79869181699700","public_key":{"hex_bytes":"0405e82ac561143aafc13ba109677a597c8f797b07417d0addd7a346ad35882b3c4a006620e02127b9a32e90979ff93ecad0a2f577db238163a50023e393e354ff","curve_type":"secp256k1"},"signing_payload":{"hex_bytes":"0206e22e9bded068a76f89a86e0849b7e6ff8f6e8a22e1b679fd87a08635a9f2","address":"0x5aCB42b3cfCD734a57AFF800139ba1354b549159"},"signature_type":"ecdsa_recovery"}]`
	var signatures []*types.Signature
	assert.NoError(t, json.Unmarshal([]byte(signaturesRaw), &signatures))
	signedRaw := `{"type":"0x2","nonce":"0x0","gasPrice":null,"maxPriorityFeePerGas":"0x59682f00","maxFeePerGas":"0xe51af8700","gas":"0x5208","value":"0x3e8","input":"0x","v":"0x0","r":"0x9f2f61a9a90f6695b10ed04102dca3e0aa50a10263afd861761226e3e61903a6","s":"0x2fb42a9e8d96af626e64fd20573338f41d4f90ea9834ce6aa4ff798691816997","to":"0x3fa177c2e87cb24148ec403921db577d140cc07c","chainId":"0x13881","accessList":[],"hash":"0xa7c55d7deafc3a717c36162b1dad13b7738ff5898dce3c946dd879e2e73ce840"}` //nolint
	combineResponse, err := servicer.ConstructionCombine(ctx, &types.ConstructionCombineRequest{
		NetworkIdentifier:   networkIdentifier,
		UnsignedTransaction: unsignedRaw,
		Signatures:          signatures,
	})

	fmt.Printf("resulting payload: %v\n", combineResponse.SignedTransaction)

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
		Hash: "0xfacf81ceb293b34292ea428c64a4a550fd5702432908a952aa9d1db455c22c72",
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
			"0212e9f98d9750e5f74b4b4b00df39074f86c79187943bdb3c5a9c89ffc1ed0188",
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
			Address: "0xD10a72Cf054650931365Cc44D912a4FD75257058",
		},
	}, deriveResponse)

	// Test Preprocess
	intent := `[{"operation_identifier":{"index":0},"type":"CALL","account":{"address":"0x5aCB42b3cfCD734a57AFF800139ba1354b549159"},"amount":{"value":"-1000","currency":{"symbol":"MATIC","decimals":18}}},{"operation_identifier":{"index":1},"related_operations":[{"index":0}],"type":"CALL","account":{"address":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c"},"amount":{"value":"1000","currency":{"symbol":"MATIC","decimals":18}}}]`
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
	optionsRaw := `{"from":"0x5aCB42b3cfCD734a57AFF800139ba1354b549159","nonce":"0x1","to":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c","value":"0x3e8"}`
	var options options
	assert.NoError(t, json.Unmarshal([]byte(optionsRaw), &options))
	assert.Equal(t, &types.ConstructionPreprocessResponse{
		Options: forceMarshalMap(t, &options),
	}, preprocessResponse)

	// Test Metadata
	metadata := &metadata{
		GasLimit: 21000,
		GasTip:   big.NewInt(1500000000),
		GasCap:   big.NewInt(1501000000),
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
				Value:    "31510500000000",
				Currency: polygon.Currency,
			},
		},
	}, metadataResponse)

	// Test Payloads
	unsignedRaw := `{"from":"0x5aCB42b3cfCD734a57AFF800139ba1354b549159","to":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c","value":"0x3e8","data":"0x","nonce":"0x1","max_fee_per_gas":"0xe51af8700","max_priority_fee_per_gas":"0x59682f00","gas":"0x5208","chain_id":"0x13881"}`
	payloadsResponse, err := servicer.ConstructionPayloads(ctx, &types.ConstructionPayloadsRequest{
		NetworkIdentifier: networkIdentifier,
		Operations:        ops,
		Metadata:          forceMarshalMap(t, metadata),
	})
	assert.Nil(t, err)
	payloadsRaw := `[{"address":"0x5aCB42b3cfCD734a57AFF800139ba1354b549159","hex_bytes":"2fbbd3c6a16a992785dbb6d6f3589d26dbc277aa83657b130b960c0da2422670","account_identifier":{"address":"0x5aCB42b3cfCD734a57AFF800139ba1354b549159"},"signature_type":"ecdsa_recovery"}]`
	var payloads []*types.SigningPayload
	assert.NoError(t, json.Unmarshal([]byte(payloadsRaw), &payloads))
	assert.Equal(t, &types.ConstructionPayloadsResponse{
		UnsignedTransaction: unsignedRaw,
		Payloads:            payloads,
	}, payloadsResponse)

	// Test Parse Unsigned
	parseOpsRaw := `[{"operation_identifier":{"index":0},"type":"CALL","account":{"address":"0x5aCB42b3cfCD734a57AFF800139ba1354b549159"},"amount":{"value":"-1000","currency":{"symbol":"MATIC","decimals":18}}},{"operation_identifier":{"index":1},"related_operations":[{"index":0}],"type":"CALL","account":{"address":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c"},"amount":{"value":"1000","currency":{"symbol":"MATIC","decimals":18}}}]`
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
	signaturesRaw := `[{"hex_bytes":"188597fb9e64a6875ceb033cd55910add342dc9ea5130f8c95010cd74366dc217de32a0d4b3da60dcce83f44b43cd9e733ded9c5da53a4d08b662b8d9e1c32c100","public_key":{"hex_bytes":"0405e82ac561143aafc13ba109677a597c8f797b07417d0addd7a346ad35882b3c4a006620e02127b9a32e90979ff93ecad0a2f577db238163a50023e393e354ff","curve_type":"secp256k1"},"signing_payload":{"hex_bytes":"2fbbd3c6a16a992785dbb6d6f3589d26dbc277aa83657b130b960c0da2422670","address":"0x5aCB42b3cfCD734a57AFF800139ba1354b549159"},"signature_type":"ecdsa_recovery"}]`
	var signatures []*types.Signature
	assert.NoError(t, json.Unmarshal([]byte(signaturesRaw), &signatures))
	signedRaw := `{"type":"0x2","nonce":"0x1","gasPrice":null,"maxPriorityFeePerGas":"0x59682f00","maxFeePerGas":"0xe51af8700","gas":"0x5208","value":"0x3e8","input":"0x","v":"0x0","r":"0x188597fb9e64a6875ceb033cd55910add342dc9ea5130f8c95010cd74366dc21","s":"0x7de32a0d4b3da60dcce83f44b43cd9e733ded9c5da53a4d08b662b8d9e1c32c1","to":"0x3fa177c2e87cb24148ec403921db577d140cc07c","chainId":"0x13881","accessList":[],"hash":"0x69589b9f54bfe4a25c807c9d4dac1ebf305b7e806437ebe4cc113b7847439aab"}` // nolint
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
		Hash: "0x69589b9f54bfe4a25c807c9d4dac1ebf305b7e806437ebe4cc113b7847439aab",
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

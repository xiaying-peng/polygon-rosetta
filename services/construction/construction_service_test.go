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

	transferGasCap           = uint64(30000000000)                         // 30 gwei
	transferGasTip           = uint64(30000000000)                         // 30 gwei, accounts for floor
	transferGasTipHex        = hexutil.EncodeUint64(transferGasTip)        // 0x6FC23AC00
	transferGasTipEstimate   = uint64(3000000000)                          // 3 gwei
	transferGasCapWithTip    = 2*transferGasCap + transferGasTip           // 90 gwei
	transferGasCapWithTipHex = hexutil.EncodeUint64(transferGasCapWithTip) // 0x14F46B0400
	minGasCap                = big.NewInt(30000000000)

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
	tipMultiplier = 1.0 // These tests were created before we introduced a tip multiplier
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
		GasTip:   big.NewInt(int64(transferGasTip)),
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
		big.NewInt(int64(transferGasTipEstimate)), // this value is to be overriden by the 30 gwei min
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
				Value:    "1890000000000000",
				Currency: polygon.Currency,
			},
		},
	}, metadataResponse)

	// Test Payloads
	unsignedRaw := `{"from":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1","to":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c","value":"0x3e8","data":"0x","nonce":"0x0","max_fee_per_gas":"0x14f46b0400","max_priority_fee_per_gas":"0x6fc23ac00","gas":"0x5208","chain_id":"0x13881"}`
	payloadsResponse, err := servicer.ConstructionPayloads(ctx, &types.ConstructionPayloadsRequest{
		NetworkIdentifier: networkIdentifier,
		Operations:        ops,
		Metadata:          forceMarshalMap(t, metadata1),
	})
	assert.Nil(t, err)

	payloadsRaw := `[{"address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1","hex_bytes":"bf0f517f63d9361336b5cc7b3a17b90bc0823a8085dc438347c5cbaf8f7520f5","account_identifier":{"address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1"},"signature_type":"ecdsa_recovery"}]`
	var payloads []*types.SigningPayload
	assert.NoError(t, json.Unmarshal([]byte(payloadsRaw), &payloads))
	fmt.Printf("raw payloads: %x\n", payloads[0].Bytes)
	fmt.Printf("raw payloads response: %x\n", payloadsResponse.Payloads[0].Bytes)
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
	signaturesRaw := `[{"hex_bytes":"e643c47c16458bbde6503e2366257b2dee723cdc64d2de1584d3145bcaa6412e3438b4439b37dbe7894237a20d0e6b21e69c2357c09eab723200dd35fb1f01bf01","public_key":{"hex_bytes":"df5c7854e2264f641773f12fa3ce186ef1ebb294a7842ae7f3ef46ba502f7bffc990442f989d091ddaac352651de2d6f20fa0e65cc32d5283777177a41f51b7d","curve_type":"secp256k1"},"signing_payload":{"hex_bytes":"bf0f517f63d9361336b5cc7b3a17b90bc0823a8085dc438347c5cbaf8f7520f5","address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1"},"signature_type":"ecdsa_recovery"}]`
	var signatures []*types.Signature
	assert.NoError(t, json.Unmarshal([]byte(signaturesRaw), &signatures))
	signedRaw := `{"type":"0x2","nonce":"0x0","gasPrice":null,"maxPriorityFeePerGas":"0x6fc23ac00","maxFeePerGas":"0x14f46b0400","gas":"0x5208","value":"0x3e8","input":"0x","v":"0x1","r":"0xe643c47c16458bbde6503e2366257b2dee723cdc64d2de1584d3145bcaa6412e","s":"0x3438b4439b37dbe7894237a20d0e6b21e69c2357c09eab723200dd35fb1f01bf","to":"0x3fa177c2e87cb24148ec403921db577d140cc07c","chainId":"0x13881","accessList":[],"hash":"0x7edd5ef60a7c66eac3774cfed297517869c66dc92b2dcd1e6346045241b10775"}` //nolint
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
		Hash: "0x7edd5ef60a7c66eac3774cfed297517869c66dc92b2dcd1e6346045241b10775",
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

	// Test with non-1.0 gas tip multiplier
	tipMultiplier = 1.2
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
		big.NewInt(int64(transferGasTipEstimate)), // this value is to be overriden by the 30 gwei min
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

	gasTip := multiplyBigInt(big.NewInt(int64(transferGasTip)), tipMultiplier)
	gasCap := new(big.Int).Add(gasTip, big.NewInt(60000000000)) // tip + baseFee*2

	metadata2 := &metadata{
		GasLimit: 21000,
		GasTip:   gasTip,
		GasCap:   gasCap,
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
				Value:    "2016000000000000", // (2*30gwei + 1.2*30gwei) * 21000
				Currency: polygon.Currency,
			},
		},
	}, metadataResponse)
}

func TestConstructionFlowWithInputNonce(t *testing.T) {
	tipMultiplier = 1.0 // These tests were created before there was a tip multiplier
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
				Value:    "1890000000000000",
				Currency: polygon.Currency,
			},
		},
	}, metadataResponse)

	// Test Payloads
	unsignedRaw := `{"from":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1","to":"0x3Fa177c2E87Cb24148EC403921dB577d140CC07c","value":"0x3e8","data":"0x","nonce":"0x1","max_fee_per_gas":"0x14f46b0400","max_priority_fee_per_gas":"0x6fc23ac00","gas":"0x5208","chain_id":"0x13881"}`
	payloadsResponse, err := servicer.ConstructionPayloads(ctx, &types.ConstructionPayloadsRequest{
		NetworkIdentifier: networkIdentifier,
		Operations:        ops,
		Metadata:          forceMarshalMap(t, metadata),
	})
	assert.Nil(t, err)
	payloadsRaw := `[{"address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1","hex_bytes":"6d7310e879e0db88071aef86a9ae4ccc8459a07fb9b6b9c468dc499453fa4994","account_identifier":{"address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1"},"signature_type":"ecdsa_recovery"}]`
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
	signaturesRaw := `[{"hex_bytes":"46f411fd39f8cc5be99b67e398c2e35924c8ab185bb04df855e705479907fb7608be2b9afab67499edffeec81a0d35c3abfcb92430da50e2f448b4b95befc20001","public_key":{"hex_bytes":"0405e82ac561143aafc13ba109677a597c8f797b07417d0addd7a346ad35882b3c4a006620e02127b9a32e90979ff93ecad0a2f577db238163a50023e393e354ff","curve_type":"secp256k1"},"signing_payload":{"hex_bytes":"6d7310e879e0db88071aef86a9ae4ccc8459a07fb9b6b9c468dc499453fa4994","address":"0xda75C156Bc4b518ac4b91Ee942BE2B2e2e36e8C1"},"signature_type":"ecdsa_recovery"}]`
	var signatures []*types.Signature
	assert.NoError(t, json.Unmarshal([]byte(signaturesRaw), &signatures))
	signedRaw := `{"type":"0x2","nonce":"0x1","gasPrice":null,"maxPriorityFeePerGas":"0x6fc23ac00","maxFeePerGas":"0x14f46b0400","gas":"0x5208","value":"0x3e8","input":"0x","v":"0x1","r":"0x46f411fd39f8cc5be99b67e398c2e35924c8ab185bb04df855e705479907fb76","s":"0x8be2b9afab67499edffeec81a0d35c3abfcb92430da50e2f448b4b95befc200","to":"0x3fa177c2e87cb24148ec403921db577d140cc07c","chainId":"0x13881","accessList":[],"hash":"0xbedd18dd52d029d63cbb87630c6ebaa689fc83cb996f7035c5630dd796ac9f77"}` // nolint
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
		Hash: "0xbedd18dd52d029d63cbb87630c6ebaa689fc83cb996f7035c5630dd796ac9f77",
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

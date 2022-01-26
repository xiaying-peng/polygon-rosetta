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
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"math/big"

	"github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/maticnetwork/polygon-rosetta/polygon"

	"golang.org/x/crypto/sha3"
)

// *JSONMap functions are needed because `types.MarshalMap/types.UnmarshalMap`
// does not respect custom JSON marshalers.

// marshalJSONMap converts an interface into a map[string]interface{}.
func marshalJSONMap(i interface{}) (map[string]interface{}, error) {
	b, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}

	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}

	return m, nil
}

// unmarshalJSONMap converts map[string]interface{} into a interface{}.
func unmarshalJSONMap(m map[string]interface{}, i interface{}) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}

	return json.Unmarshal(b, i)
}

// erc20TransferMethodID calculates the first 4 bytes of the method
// signature for transfer on an ERC20 contract
func erc20TransferMethodID() ([]byte, error) {
	transferFnSignature := []byte("transfer(address,uint256)")
	hash := sha3.NewLegacyKeccak256()
	if _, err := hash.Write(transferFnSignature); err != nil {
		return nil, err
	}

	return hash.Sum(nil)[:4], nil
}

// hasData determines if the data or input on a transfer
// transaction is empty or not.
func hasData(data []byte) bool {
	return len(data) > 0
}

// erc20TransferArgs returns the arguments for an ERC20 transfer,
// including destination address and value
func erc20TransferArgs(data []byte) (string, *big.Int, error) {
	if data == nil || len(data) != 4+32+32 {
		return "", nil, errors.New("invalid data")
	}
	methodID := data[:4]
	toAdd := common.BytesToAddress(data[4:36]).String()
	amount := big.NewInt(0).SetBytes(data[36:])

	expectedMethodID, err := erc20TransferMethodID()
	if err != nil {
		return "", nil, err
	}
	if res := bytes.Compare(methodID, expectedMethodID); res != 0 {
		return "", nil, errors.New("invalid method id")
	}

	return toAdd, amount, nil
}

func rosettaOperations(
	fromAddress string,
	toAddress string,
	amount *big.Int,
	currency *types.Currency,
) []*types.Operation {
	return []*types.Operation{
		{
			OperationIdentifier: &types.OperationIdentifier{
				Index: 0,
			},
			Type: polygon.CallOpType,
			Account: &types.AccountIdentifier{
				Address: fromAddress,
			},
			Amount: &types.Amount{
				Value:    new(big.Int).Neg(amount).String(),
				Currency: currency,
			},
		},
		{
			OperationIdentifier: &types.OperationIdentifier{
				Index: 1,
			},
			RelatedOperations: []*types.OperationIdentifier{
				{
					Index: 0,
				},
			},
			Type: polygon.CallOpType,
			Account: &types.AccountIdentifier{
				Address: toAddress,
			},
			Amount: &types.Amount{
				Value:    amount.String(),
				Currency: currency,
			},
		},
	}
}

// contractCallMethodID calculates the first 4 bytes of the method
// signature for function call on contract
func contractCallMethodID(methodSig string) ([]byte, error) {
	fnSignature := []byte(methodSig)
	hash := sha3.NewLegacyKeccak256()
	if _, err := hash.Write(fnSignature); err != nil {
		log.Fatal(err)
	}

	return hash.Sum(nil)[:4], nil
}

func hasTransferData(data []byte) bool {
	methodID := data[:4]
	expectedMethodID, _ := erc20TransferMethodID()
	res := bytes.Compare(methodID, expectedMethodID)
	if res != 0 {
		return false
	}
	return true
}

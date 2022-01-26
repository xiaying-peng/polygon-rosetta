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
	"fmt"

	"github.com/coinbase/rosetta-sdk-go/types"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/maticnetwork/polygon-rosetta/polygon"
	svcErrors "github.com/maticnetwork/polygon-rosetta/services/errors"
)

// ConstructionParse implements the /construction/parse endpoint.
func (a *APIService) ConstructionParse(
	ctx context.Context,
	request *types.ConstructionParseRequest,
) (*types.ConstructionParseResponse, *types.Error) {
	var tx transaction
	if !request.Signed {
		err := json.Unmarshal([]byte(request.Transaction), &tx)
		if err != nil {
			return nil, svcErrors.WrapErr(svcErrors.ErrUnableToParseIntermediateResult, err)
		}
	} else {
		t := new(ethTypes.Transaction)
		err := t.UnmarshalJSON([]byte(request.Transaction))
		if err != nil {
			return nil, svcErrors.WrapErr(svcErrors.ErrUnableToParseIntermediateResult, err)
		}

		tx.To = t.To().String()
		tx.Value = t.Value()
		tx.Data = t.Data()
		tx.Nonce = t.Nonce()
		tx.GasPrice = t.GasPrice()
		tx.GasLimit = t.Gas()
		tx.ChainID = t.ChainId()

		msg, err := t.AsMessage(ethTypes.NewEIP155Signer(t.ChainId()), nil)
		if err != nil {
			return nil, svcErrors.WrapErr(svcErrors.ErrUnableToParseIntermediateResult, err)
		}

		tx.From = msg.From().Hex()
	}

	// Native currency
	currency := polygon.Currency

	//TODO: add logic for contract call parsing
	// ERC20 currency
	if hasData(tx.Data) && hasTransferData(tx.Data) {
		toAdd, amount, err := erc20TransferArgs(tx.Data)
		if err != nil {
			return nil, svcErrors.WrapErr(svcErrors.ErrUnableToParseTransaction, err)
		}

		// TODO: wrap ethTypes.Transaction with currency so that we can properly show symbol
		currency = &types.Currency{
			Symbol:   "ERC20",
			Decimals: 18, //nolint
			Metadata: map[string]interface{}{
				TokenContractAddressKey: tx.To,
			},
		}

		// Update destination address to be the actual recipient
		tx.To = toAdd
		tx.Value = amount
	}

	// Ensure valid from address
	checkFrom, ok := polygon.ChecksumAddress(tx.From)
	if !ok {
		return nil, svcErrors.WrapErr(svcErrors.ErrInvalidAddress, fmt.Errorf("%s is not a valid address", tx.From))
	}

	// Ensure valid to address
	checkTo, ok := polygon.ChecksumAddress(tx.To)
	if !ok {
		return nil, svcErrors.WrapErr(svcErrors.ErrInvalidAddress, fmt.Errorf("%s is not a valid address", tx.To))
	}

	ops := rosettaOperations(checkFrom, checkTo, tx.Value, currency)

	metadata := &parseMetadata{
		Nonce:    tx.Nonce,
		GasPrice: tx.GasPrice,
		GasLimit: tx.GasLimit,
		ChainID:  tx.ChainID,
	}
	metaMap, err := marshalJSONMap(metadata)
	if err != nil {
		return nil, svcErrors.WrapErr(svcErrors.ErrUnableToParseIntermediateResult, err)
	}

	var resp *types.ConstructionParseResponse
	if request.Signed {
		resp = &types.ConstructionParseResponse{
			Operations: ops,
			AccountIdentifierSigners: []*types.AccountIdentifier{
				{
					Address: checkFrom,
				},
			},
			Metadata: metaMap,
		}
	} else {
		resp = &types.ConstructionParseResponse{
			Operations:               ops,
			AccountIdentifierSigners: []*types.AccountIdentifier{},
			Metadata:                 metaMap,
		}
	}
	return resp, nil
}

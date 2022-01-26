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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/maticnetwork/polygon-rosetta/polygon"
	svcErrors "github.com/maticnetwork/polygon-rosetta/services/errors"
)

// ConstructionPayloads implements the /construction/payloads endpoint.
func (a *APIService) ConstructionPayloads(
	ctx context.Context,
	request *types.ConstructionPayloadsRequest,
) (*types.ConstructionPayloadsResponse, *types.Error) {

	// Convert map to Metadata struct
	var metadata metadata
	if err := unmarshalJSONMap(request.Metadata, &metadata); err != nil {
		return nil, svcErrors.WrapErr(svcErrors.ErrUnableToParseIntermediateResult, err)
	}
	isContractCall := false
	if hasData(metadata.Data) && !hasTransferData(metadata.Data) {
		isContractCall = true
	}

	fromOp, toOp, err := matchTransferOperations(request.Operations, isContractCall)
	if err != nil {
		return nil, svcErrors.WrapErr(svcErrors.ErrUnclearIntent, err)
	}

	if err := validateRequest(fromOp, toOp, metadata); err != nil {
		return nil, svcErrors.WrapErr(svcErrors.ErrBadRequest, err)
	}

	// Required Fields for constructing a real Polygon transaction
	fromAdd := fromOp.Account.Address
	amount := metadata.Value
	toAdd := metadata.To
	nonce := metadata.Nonce
	gasPrice := metadata.GasPrice
	chainID := a.config.Params.ChainID
	transferGasLimit := metadata.GasLimit.Uint64()
	transferData := metadata.Data

	// Ensure valid from address
	checkFrom, ok := polygon.ChecksumAddress(fromAdd)
	if !ok {
		return nil, svcErrors.WrapErr(svcErrors.ErrInvalidAddress, fmt.Errorf("%s is not a valid address", fromAdd))
	}

	// Ensure valid to address
	checkTo, ok := polygon.ChecksumAddress(toAdd)
	if !ok {
		return nil, svcErrors.WrapErr(svcErrors.ErrInvalidAddress, fmt.Errorf("%s is not a valid address", toAdd))
	}

	tx := ethTypes.NewTransaction(
		nonce,
		common.HexToAddress(checkTo),
		amount,
		transferGasLimit,
		gasPrice,
		transferData,
	)

	unsignedTx := &transaction{
		From:     checkFrom,
		To:       checkTo,
		Value:    amount,
		Data:     tx.Data(),
		Nonce:    tx.Nonce(),
		GasPrice: gasPrice,
		GasLimit: tx.Gas(),
		ChainID:  chainID,
	}

	// Construct SigningPayload
	signer := ethTypes.NewEIP155Signer(chainID)
	payload := &types.SigningPayload{
		AccountIdentifier: &types.AccountIdentifier{Address: checkFrom},
		Bytes:             signer.Hash(tx).Bytes(),
		SignatureType:     types.EcdsaRecovery,
	}

	unsignedTxJSON, err := json.Marshal(unsignedTx)
	if err != nil {
		return nil, svcErrors.WrapErr(svcErrors.ErrUnableToParseIntermediateResult, err)
	}

	return &types.ConstructionPayloadsResponse{
		UnsignedTransaction: string(unsignedTxJSON),
		Payloads:            []*types.SigningPayload{payload},
	}, nil
}

// validateRequest validates if the intent in operations matches
// the intent in metadata of this particular request
func validateRequest(
	fromOp *types.Operation,
	toOp *types.Operation,
	metadata metadata,
) error {
	if !hasData(metadata.Data) {
		// Native currency
		// Validate destination address
		if metadata.To != toOp.Account.Address {
			return errors.New("mismatch destination address")
		}
		// Validate transfer value
		if metadata.Value.String() != toOp.Amount.Value {
			return errors.New("mismatch transfer value")
		}
	} else if hasTransferData(metadata.Data) {
		// ERC20
		toAdd, amount, err := erc20TransferArgs(metadata.Data)
		if err != nil {
			return err
		}
		// Validate destination address
		if toAdd != toOp.Account.Address {
			return errors.New("mismatch destination address")
		}
		// Validate transfer value
		if amount.String() != toOp.Amount.Value {
			return errors.New("mismatch transfer value")
		}
		// Validate metadata value
		if metadata.Value.String() != "0" {
			return errors.New("invalid metadata value")
		}
	} else if hasData(metadata.Data) && !hasTransferData(metadata.Data) {

		//contract call
		data, err := constructContractCallData(metadata.MethodSignature, metadata.MethodArgs)
		if err != nil {
			return err
		}
		res := bytes.Compare(data, metadata.Data)
		if res != 0 {
			return errors.New("invalid data value")
		}
	}

	return nil
}

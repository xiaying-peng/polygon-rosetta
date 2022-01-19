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
	"errors"

	"github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	svcErrors "github.com/maticnetwork/polygon-rosetta/services/errors"
)

// ConstructionCombine implements the /construction/combine
// endpoint.
func (a *APIService) ConstructionCombine(
	ctx context.Context,
	request *types.ConstructionCombineRequest,
) (*types.ConstructionCombineResponse, *types.Error) {
	var unsignedTx transaction
	if len(request.UnsignedTransaction) == 0 {
		return nil, svcErrors.WrapErr(svcErrors.ErrInvalidTransaction, errors.New("transaction data is not provided"))
	}
	if len(request.Signatures) == 0 {
		return nil, svcErrors.WrapErr(svcErrors.ErrInvalidSignature, errors.New("signature is not provided"))
	}

	if err := json.Unmarshal([]byte(request.UnsignedTransaction), &unsignedTx); err != nil {
		return nil, svcErrors.WrapErr(svcErrors.ErrUnableToParseIntermediateResult, err)
	}

	ethTransaction := ethTypes.NewTransaction(
		unsignedTx.Nonce,
		common.HexToAddress(unsignedTx.To),
		unsignedTx.Value,
		unsignedTx.GasLimit,
		unsignedTx.GasPrice,
		unsignedTx.Data,
	)

	signer := ethTypes.NewEIP155Signer(unsignedTx.ChainID)
	signedTx, err := ethTransaction.WithSignature(signer, request.Signatures[0].Bytes)
	if err != nil {
		return nil, svcErrors.WrapErr(svcErrors.ErrInvalidSignature, err)
	}

	// TODO differentiate this from the unmarshal error above
	signedTxJSON, err := signedTx.MarshalJSON()
	if err != nil {
		return nil, svcErrors.WrapErr(svcErrors.ErrUnableToParseIntermediateResult, err)
	}

	return &types.ConstructionCombineResponse{
		SignedTransaction: string(signedTxJSON),
	}, nil
}

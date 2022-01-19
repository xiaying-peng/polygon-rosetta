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
	"errors"

	"github.com/coinbase/rosetta-sdk-go/types"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	svcErrors "github.com/maticnetwork/polygon-rosetta/services/errors"
)

// ConstructionHash implements the /construction/hash endpoint.
func (a *APIService) ConstructionHash(
	ctx context.Context,
	request *types.ConstructionHashRequest,
) (*types.TransactionIdentifierResponse, *types.Error) {
	signedTx := ethTypes.Transaction{}
	if len(request.SignedTransaction) == 0 {
		return nil, svcErrors.WrapErr(svcErrors.ErrInvalidSignature, errors.New("signed transaction value is not provided"))
	}

	if err := signedTx.UnmarshalJSON([]byte(request.SignedTransaction)); err != nil {
		return nil, svcErrors.WrapErr(svcErrors.ErrUnableToParseIntermediateResult, err)
	}

	hash := signedTx.Hash().Hex()

	return &types.TransactionIdentifierResponse{
		TransactionIdentifier: &types.TransactionIdentifier{
			Hash: hash,
		},
	}, nil
}

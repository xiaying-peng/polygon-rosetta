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
	"github.com/ethereum/go-ethereum/crypto"
	svcErrors "github.com/maticnetwork/polygon-rosetta/services/errors"
)

// ConstructionDerive implements the /construction/derive endpoint.
func (a *APIService) ConstructionDerive(
	ctx context.Context,
	request *types.ConstructionDeriveRequest,
) (*types.ConstructionDeriveResponse, *types.Error) {
	if request.PublicKey == nil {
		return nil, svcErrors.WrapErr(svcErrors.ErrInvalidPublicKey, errors.New("public key is not provided"))
	}

	pubkey, err := crypto.DecompressPubkey(request.PublicKey.Bytes)
	if err != nil {
		return nil, svcErrors.WrapErr(svcErrors.ErrUnableToDecompressPubkey, err)
	}

	addr := crypto.PubkeyToAddress(*pubkey)
	return &types.ConstructionDeriveResponse{
		AccountIdentifier: &types.AccountIdentifier{
			Address: addr.Hex(),
		},
	}, nil
}

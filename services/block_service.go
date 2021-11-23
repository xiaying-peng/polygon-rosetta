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

package services

import (
	"context"
	"errors"

	"github.com/maticnetwork/polygon-rosetta/services/construction"
	svcErrors "github.com/maticnetwork/polygon-rosetta/services/errors"

	"github.com/maticnetwork/polygon-rosetta/configuration"
	"github.com/maticnetwork/polygon-rosetta/polygon"

	"github.com/coinbase/rosetta-sdk-go/types"
)

// BlockAPIService implements the server.BlockAPIServicer interface.
type BlockAPIService struct {
	config *configuration.Configuration
	client construction.Client
}

// NewBlockAPIService creates a new instance of a BlockAPIService.
func NewBlockAPIService(
	cfg *configuration.Configuration,
	client construction.Client,
) *BlockAPIService {
	return &BlockAPIService{
		config: cfg,
		client: client,
	}
}

// Block implements the /block endpoint.
func (s *BlockAPIService) Block(
	ctx context.Context,
	request *types.BlockRequest,
) (*types.BlockResponse, *types.Error) {
	if s.config.Mode != configuration.Online {
		return nil, svcErrors.ErrUnavailableOffline
	}

	block, err := s.client.Block(ctx, request.BlockIdentifier)
	if errors.Is(err, polygon.ErrBlockOrphaned) {
		return nil, svcErrors.WrapErr(svcErrors.ErrBlockOrphaned, err)
	}
	if err != nil {
		return nil, svcErrors.WrapErr(svcErrors.ErrGeth, err)
	}

	return &types.BlockResponse{
		Block: block,
	}, nil
}

// BlockTransaction implements the /block/transaction endpoint.
func (s *BlockAPIService) BlockTransaction(
	ctx context.Context,
	request *types.BlockTransactionRequest,
) (*types.BlockTransactionResponse, *types.Error) {
	return nil, svcErrors.WrapErr(svcErrors.ErrUnimplemented, nil)
}

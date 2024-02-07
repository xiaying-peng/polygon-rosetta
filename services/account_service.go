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

	"github.com/xiaying-peng/polygon-rosetta/services/construction"
	"github.com/xiaying-peng/polygon-rosetta/services/errors"

	"github.com/xiaying-peng/polygon-rosetta/configuration"

	"github.com/coinbase/rosetta-sdk-go/types"
)

// AccountAPIService implements the server.AccountAPIServicer interface.
type AccountAPIService struct {
	config *configuration.Configuration
	client construction.Client
}

// NewAccountAPIService returns a new *AccountAPIService.
func NewAccountAPIService(
	cfg *configuration.Configuration,
	client construction.Client,
) *AccountAPIService {
	return &AccountAPIService{
		config: cfg,
		client: client,
	}
}

// AccountBalance implements /account/balance.
func (s *AccountAPIService) AccountBalance(
	ctx context.Context,
	request *types.AccountBalanceRequest,
) (*types.AccountBalanceResponse, *types.Error) {
	if s.config.Mode != configuration.Online {
		return nil, errors.ErrUnavailableOffline
	}

	balanceResponse, err := s.client.Balance(
		ctx,
		request.AccountIdentifier,
		request.BlockIdentifier,
		request.Currencies,
	)
	if err != nil {
		return nil, errors.WrapErr(errors.ErrGeth, err)
	}

	return balanceResponse, nil
}

// AccountCoins implements /account/coins.
func (s *AccountAPIService) AccountCoins(
	ctx context.Context,
	request *types.AccountCoinsRequest,
) (*types.AccountCoinsResponse, *types.Error) {
	return nil, errors.WrapErr(errors.ErrUnimplemented, nil)
}

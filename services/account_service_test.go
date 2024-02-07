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
	"testing"

	"github.com/xiaying-peng/polygon-rosetta/services/errors"

	"github.com/xiaying-peng/polygon-rosetta/configuration"
	mocks "github.com/xiaying-peng/polygon-rosetta/mocks/services"
	"github.com/xiaying-peng/polygon-rosetta/polygon"

	"github.com/coinbase/rosetta-sdk-go/types"
	"github.com/stretchr/testify/assert"
)

func TestAccountBalance_Offline(t *testing.T) {
	cfg := &configuration.Configuration{
		Mode: configuration.Offline,
	}
	mockClient := &mocks.Client{}
	servicer := NewAccountAPIService(cfg, mockClient)
	ctx := context.Background()

	bal, err := servicer.AccountBalance(ctx, &types.AccountBalanceRequest{})
	assert.Nil(t, bal)
	assert.Equal(t, errors.ErrUnavailableOffline.Code, err.Code)

	coins, err := servicer.AccountCoins(ctx, nil)
	assert.Nil(t, coins)
	assert.Equal(t, errors.ErrUnimplemented.Code, err.Code)
	assert.Equal(t, errors.ErrUnimplemented.Message, err.Message)

	mockClient.AssertExpectations(t)
}

var mockCurrency = &types.Currency{
	Symbol:   "mock",
	Decimals: 18,
	Metadata: map[string]interface{}{
		"contractAddress": "0x4a1b31b1bd1c691622bb27a55155c01137bd532c",
	},
}

func TestAccountBalance_Online(t *testing.T) {
	cfg := &configuration.Configuration{
		Mode: configuration.Online,
	}
	mockClient := &mocks.Client{}
	servicer := NewAccountAPIService(cfg, mockClient)

	ctx := context.Background()

	account := &types.AccountIdentifier{
		Address: "hello",
	}

	block := &types.BlockIdentifier{
		Index: 1000,
		Hash:  "block 1000",
	}

	resp := &types.AccountBalanceResponse{
		BlockIdentifier: block,
		Balances: []*types.Amount{
			{
				Value:    "25",
				Currency: polygon.Currency,
			},
			{
				Value:    "1000",
				Currency: mockCurrency,
			},
		},
	}

	mockClient.On(
		"Balance",
		ctx,
		account,
		types.ConstructPartialBlockIdentifier(block),
		[]*types.Currency{mockCurrency},
	).Return(resp, nil).Once()

	bal, err := servicer.AccountBalance(ctx, &types.AccountBalanceRequest{
		AccountIdentifier: account,
		BlockIdentifier:   types.ConstructPartialBlockIdentifier(block),
		Currencies: []*types.Currency{
			mockCurrency,
		},
	})
	assert.Nil(t, err)
	assert.Equal(t, resp, bal)

	coins, err := servicer.AccountCoins(ctx, nil)
	assert.Nil(t, coins)
	assert.Equal(t, errors.ErrUnimplemented.Code, err.Code)
	assert.Equal(t, errors.ErrUnimplemented.Message, err.Message)

	mockClient.AssertExpectations(t)
}

func TestAccountBalances_Online(t *testing.T) {
	cfg := &configuration.Configuration{
		Mode: configuration.Online,
	}
	mockClient := &mocks.Client{}
	servicer := NewAccountAPIService(cfg, mockClient)

	ctx := context.Background()

	account := &types.AccountIdentifier{
		Address: "hello",
	}

	block := &types.BlockIdentifier{
		Index: 1000,
		Hash:  "block 1000",
	}

	currencies := []*types.Currency{
		mockCurrency,
	}

	resp := &types.AccountBalanceResponse{
		BlockIdentifier: block,
		Balances: []*types.Amount{
			{
				Value:    "25",
				Currency: polygon.Currency,
			},
			{
				Value:    "100",
				Currency: mockCurrency,
				Metadata: map[string]interface{}{
					"status":  1,
					"gasUsed": 1,
				},
			},
		},
	}

	mockClient.On(
		"Balance",
		ctx,
		account,
		types.ConstructPartialBlockIdentifier(block),
		currencies,
	).Return(resp, nil).Once()

	bal, err := servicer.AccountBalance(ctx, &types.AccountBalanceRequest{
		AccountIdentifier: account,
		BlockIdentifier:   types.ConstructPartialBlockIdentifier(block),
		Currencies:        currencies,
	})
	assert.Nil(t, err)
	assert.Equal(t, resp, bal)

	coins, err := servicer.AccountCoins(ctx, nil)
	assert.Nil(t, coins)
	assert.Equal(t, errors.ErrUnimplemented.Code, err.Code)
	assert.Equal(t, errors.ErrUnimplemented.Message, err.Message)

	mockClient.AssertExpectations(t)
}

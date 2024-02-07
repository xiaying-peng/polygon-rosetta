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
	"github.com/xiaying-peng/polygon-rosetta/polygon"

	"github.com/coinbase/rosetta-sdk-go/asserter"
	"github.com/coinbase/rosetta-sdk-go/types"
)

// NetworkAPIService implements the server.NetworkAPIServicer interface.
type NetworkAPIService struct {
	config *configuration.Configuration
	client construction.Client
}

// NewNetworkAPIService creates a new instance of a NetworkAPIService.
func NewNetworkAPIService(
	cfg *configuration.Configuration,
	client construction.Client,
) *NetworkAPIService {
	return &NetworkAPIService{
		config: cfg,
		client: client,
	}
}

// NetworkList implements the /network/list endpoint
func (s *NetworkAPIService) NetworkList(
	ctx context.Context,
	request *types.MetadataRequest,
) (*types.NetworkListResponse, *types.Error) {
	return &types.NetworkListResponse{
		NetworkIdentifiers: []*types.NetworkIdentifier{s.config.Network},
	}, nil
}

// NetworkOptions implements the /network/options endpoint.
func (s *NetworkAPIService) NetworkOptions(
	ctx context.Context,
	request *types.NetworkRequest,
) (*types.NetworkOptionsResponse, *types.Error) {
	return &types.NetworkOptionsResponse{
		Version: &types.Version{
			NodeVersion:       polygon.NodeVersion,
			RosettaVersion:    types.RosettaAPIVersion,
			MiddlewareVersion: types.String(configuration.MiddlewareVersion),
		},
		Allow: &types.Allow{
			Errors:                  errors.Errors,
			OperationTypes:          polygon.OperationTypes,
			OperationStatuses:       polygon.OperationStatuses,
			HistoricalBalanceLookup: polygon.HistoricalBalanceSupported,
			CallMethods:             polygon.CallMethods,
		},
	}, nil
}

// NetworkStatus implements the /network/status endpoint.
func (s *NetworkAPIService) NetworkStatus(
	ctx context.Context,
	request *types.NetworkRequest,
) (*types.NetworkStatusResponse, *types.Error) {
	if s.config.Mode != configuration.Online {
		return nil, errors.ErrUnavailableOffline
	}

	currentBlock, currentTime, syncStatus, peers, err := s.client.Status(ctx)
	if err != nil {
		return nil, errors.WrapErr(errors.ErrGeth, err)
	}

	if currentTime < asserter.MinUnixEpoch {
		return nil, errors.ErrGethNotReady
	}

	return &types.NetworkStatusResponse{
		CurrentBlockIdentifier: currentBlock,
		CurrentBlockTimestamp:  currentTime,
		GenesisBlockIdentifier: s.config.GenesisBlockIdentifier,
		SyncStatus:             syncStatus,
		Peers:                  peers,
	}, nil
}

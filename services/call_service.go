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

// CallAPIService implements the server.CallAPIServicer interface.
type CallAPIService struct {
	config *configuration.Configuration
	client construction.Client
}

// NewCallAPIService creates a new instance of a CallAPIService.
func NewCallAPIService(cfg *configuration.Configuration, client construction.Client) *CallAPIService {
	return &CallAPIService{
		config: cfg,
		client: client,
	}
}

// Call implements the /call endpoint.
func (s *CallAPIService) Call(
	ctx context.Context,
	request *types.CallRequest,
) (*types.CallResponse, *types.Error) {
	if s.config.Mode != configuration.Online {
		return nil, svcErrors.ErrUnavailableOffline
	}

	response, err := s.client.Call(ctx, request)
	if errors.Is(err, polygon.ErrCallParametersInvalid) {
		return nil, svcErrors.WrapErr(svcErrors.ErrCallParametersInvalid, err)
	}
	if errors.Is(err, polygon.ErrCallOutputMarshal) {
		return nil, svcErrors.WrapErr(svcErrors.ErrCallOutputMarshal, err)
	}
	if errors.Is(err, polygon.ErrCallMethodInvalid) {
		return nil, svcErrors.WrapErr(svcErrors.ErrCallMethodInvalid, err)
	}
	if err != nil {
		return nil, svcErrors.WrapErr(svcErrors.ErrGeth, err)
	}

	return response, nil
}

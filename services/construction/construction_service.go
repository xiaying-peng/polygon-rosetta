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

package construction

import (
	"github.com/maticnetwork/polygon-rosetta/configuration"
)

const (
	// TokenContractAddressKey is the key in the currency metadata map
	// that represents the contract address of a token
	TokenContractAddressKey = "token_address"
)

// APIService implements the server.ConstructionAPIServicer interface.
type APIService struct {
	config *configuration.Configuration
	client Client
}

// NewAPIService creates a new instance of a APIService.
func NewAPIService(
	cfg *configuration.Configuration,
	client Client,
) *APIService {
	return &APIService{
		config: cfg,
		client: client,
	}
}

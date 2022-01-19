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

package configuration

import (
	"errors"
	"os"
	"testing"

	"github.com/maticnetwork/polygon-rosetta/polygon"

	"github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/assert"
)

func TestLoadConfiguration(t *testing.T) {
	tests := map[string]struct {
		Mode          string
		Network       string
		Port          string
		Geth          string
		SkipGethAdmin string
		GethHeaders   string

		cfg *Configuration
		err error
	}{
		"no envs set": {
			err: errors.New("MODE must be populated"),
		},
		"only mode set": {
			Mode: string(Online),
			err:  errors.New("NETWORK must be populated"),
		},
		"only mode and network set": {
			Mode:    string(Online),
			Network: Mainnet,
			err:     errors.New("PORT must be populated"),
		},
		"all set (mainnet)": {
			Mode:          string(Online),
			Network:       Mainnet,
			Port:          "1000",
			SkipGethAdmin: "FALSE",
			GethHeaders:   "",
			cfg: &Configuration{
				Mode: Online,
				Network: &types.NetworkIdentifier{
					Network:    polygon.MainnetNetwork,
					Blockchain: polygon.Blockchain,
				},
				Params:                 params.MainnetChainConfig,
				GenesisBlockIdentifier: polygon.MainnetGenesisBlockIdentifier,
				Port:                   1000,
				BorURL:                 DefaultBorURL,
				SkipGethAdmin:          false,
				GethHeaders:            nil,
				BurntContract: map[string]string{
					"23850000": "0x70bca57f4579f58670ab2d18ef16e02c17553c38",
				},
			},
		},
		"all set (mainnet) + geth": {
			Mode:          string(Online),
			Network:       Mainnet,
			Port:          "1000",
			Geth:          "http://blah",
			SkipGethAdmin: "TRUE",
			GethHeaders:   "X-Auth-Token:12345-ABCDE,X-Api-Version:2",
			cfg: &Configuration{
				Mode: Online,
				Network: &types.NetworkIdentifier{
					Network:    polygon.MainnetNetwork,
					Blockchain: polygon.Blockchain,
				},
				Params:                 params.MainnetChainConfig,
				GenesisBlockIdentifier: polygon.MainnetGenesisBlockIdentifier,
				Port:                   1000,
				BorURL:                 "http://blah",
				RemoteGeth:             true,
				SkipGethAdmin:          true,
				GethHeaders: []*polygon.HTTPHeader{
					{Key: "X-Auth-Token", Value: "12345-ABCDE"},
					{Key: "X-Api-Version", Value: "2"},
				},
				BurntContract: map[string]string{
					"23850000": "0x70bca57f4579f58670ab2d18ef16e02c17553c38",
				},
			},
		},
		"all set (mumbai)": {
			Mode:          string(Online),
			Network:       Mumbai,
			Port:          "1000",
			SkipGethAdmin: "TRUE",
			GethHeaders:   "X-Auth-Token:12345-ABCDE,X-Api-Version:2",
			cfg: &Configuration{
				Mode: Online,
				Network: &types.NetworkIdentifier{
					Network:    polygon.TestnetNetwork,
					Blockchain: polygon.Blockchain,
				},
				Params:                 params.GoerliChainConfig,
				GenesisBlockIdentifier: polygon.MumbaiGenesisBlockIdentifier,
				Port:                   1000,
				BorURL:                 DefaultBorURL,
				SkipGethAdmin:          true,
				GethHeaders: []*polygon.HTTPHeader{
					{Key: "X-Auth-Token", Value: "12345-ABCDE"},
					{Key: "X-Api-Version", Value: "2"},
				},
				BurntContract: map[string]string{
					"22640000": "0x70bcA57F4579f58670aB2d18Ef16e02C17553C38",
				},
			},
		},
		"invalid mode": {
			Mode:    "bad mode",
			Network: Mumbai,
			Port:    "1000",
			err:     errors.New("bad mode is not a valid mode"),
		},
		"invalid network": {
			Mode:    string(Offline),
			Network: "bad network",
			Port:    "1000",
			err:     errors.New("bad network is not a valid network"),
		},
		"invalid port": {
			Mode:    string(Offline),
			Network: Mumbai,
			Port:    "bad port",
			err:     errors.New("unable to parse port bad port"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			os.Setenv(ModeEnv, test.Mode)
			os.Setenv(NetworkEnv, test.Network)
			os.Setenv(PortEnv, test.Port)
			os.Setenv(BorEnv, test.Geth)
			os.Setenv(SkipGethAdminEnv, test.SkipGethAdmin)
			os.Setenv(GethHeadersEnv, test.GethHeaders)

			cfg, err := LoadConfiguration()
			if test.err != nil {
				assert.Nil(t, cfg)
				assert.Contains(t, err.Error(), test.err.Error())
			} else {
				assert.Equal(t, test.cfg, cfg)
				assert.NoError(t, err)
			}
		})
	}
}

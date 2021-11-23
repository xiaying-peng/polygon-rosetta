#!/bin/sh
# Copyright 2021 Coinbase, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

bash /app/assets/${NETWORK}/heimdall/setup.sh
SEEDS=$(cat /app/assets/${NETWORK}/heimdall/heimdall-seeds.txt)
sed -i "/seeds = \"\"/c\\$SEEDS" $HOME/.heimdalld/config/config.toml

heimdalld rest-server &
exec heimdalld start --rpc.laddr tcp://0.0.0.0:26657

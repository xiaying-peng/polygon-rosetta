#!/usr/bin/env sh
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


# set -x #echo on

BOR_DIR=${BOR_DIR:-~/.bor}
DATA_DIR=$BOR_DIR/data
NODE_KEY=~/nodekey

# create bor and keystore directory
mkdir -p $BOR_DIR $BOR_DIR/keystore

# init bor
bor --datadir $DATA_DIR init /app/assets/${NETWORK}/bor/genesis.json

# copy peers file
cp /app/assets/${NETWORK}/bor/static-nodes.json $DATA_DIR/bor/static-nodes.json

# if node key not present, create nodekey
if [ ! -f $NODE_KEY ]; then
  bootnode -genkey $NODE_KEY
fi

# copy node key file
cp $NODE_KEY $DATA_DIR/bor/

echo "Setup done!"

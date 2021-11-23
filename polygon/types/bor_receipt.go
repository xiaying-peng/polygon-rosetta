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

// from https://github.com/maticnetwork/bor/blob/3283fb9a88b414883bbe7daecee833908108ed51/core/types/bor_receipt.go
// cannot import directly due to go.mod name mismatch

package types

import (
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	borReceiptPrefix = []byte("matic-bor-receipt-") // borReceiptPrefix + number + block hash -> bor block receipt
)

// BorReceiptKey = borReceiptPrefix + num (uint64 big endian) + hash
func BorReceiptKey(number uint64, hash common.Hash) []byte {
	enc := make([]byte, 8)
	binary.BigEndian.PutUint64(enc, number)
	return append(append(borReceiptPrefix, enc...), hash.Bytes()...)
}

// GetDerivedBorTxHash get derived tx hash from receipt key
func GetDerivedBorTxHash(receiptKey []byte) common.Hash {
	return common.BytesToHash(crypto.Keccak256(receiptKey))
}

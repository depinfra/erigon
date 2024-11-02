// Copyright 2024 The Erigon Authors
// This file is part of Erigon.
//
// Erigon is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Erigon is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Erigon. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"bytes"
	"fmt"
	"math/big"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/holiman/uint256"

	libcommon "github.com/erigontech/erigon-lib/common"
	types2 "github.com/erigontech/erigon-lib/types"
	"github.com/erigontech/erigon/rlp"
)

const RUNS = 100 // for local tests increase this number

type TRand struct {
	rnd *rand.Rand
}

func NewTRand() *TRand {
	seed := time.Now().UnixNano()
	src := rand.NewSource(seed)
	return &TRand{rnd: rand.New(src)}
}

func (tr *TRand) RandIntInRange(min, max int) int {
	return (tr.rnd.Intn(max-min) + min)
}

func (tr *TRand) RandUint64() *uint64 {
	a := tr.rnd.Uint64()
	return &a
}

func (tr *TRand) RandBig() *big.Int {
	return big.NewInt(int64(tr.rnd.Int()))
}

func (tr *TRand) RandBytes(size int) []byte {
	arr := make([]byte, size)
	for i := 0; i < size; i++ {
		arr[i] = byte(tr.rnd.Intn(256))
	}
	return arr
}

func (tr *TRand) RandAddress() libcommon.Address {
	return libcommon.Address(tr.RandBytes(20))
}

func (tr *TRand) RandHash() libcommon.Hash {
	return libcommon.Hash(tr.RandBytes(32))
}

func (tr *TRand) RandBloom() Bloom {
	return Bloom(tr.RandBytes(BloomByteLength))
}

func (tr *TRand) RandWithdrawal() *Withdrawal {
	return &Withdrawal{
		Index:     tr.rnd.Uint64(),
		Validator: tr.rnd.Uint64(),
		Address:   tr.RandAddress(),
		Amount:    tr.rnd.Uint64(),
	}
}

func (tr *TRand) RandHeader() *Header {
	wHash := tr.RandHash()
	pHash := tr.RandHash()
	return &Header{
		ParentHash:            tr.RandHash(),                              // libcommon.Hash
		UncleHash:             tr.RandHash(),                              // libcommon.Hash
		Coinbase:              tr.RandAddress(),                           // libcommon.Address
		Root:                  tr.RandHash(),                              // libcommon.Hash
		TxHash:                tr.RandHash(),                              // libcommon.Hash
		ReceiptHash:           tr.RandHash(),                              // libcommon.Hash
		Bloom:                 tr.RandBloom(),                             // Bloom
		Difficulty:            tr.RandBig(),                               // *big.Int
		Number:                tr.RandBig(),                               // *big.Int
		GasLimit:              *tr.RandUint64(),                           // uint64
		GasUsed:               *tr.RandUint64(),                           // uint64
		Time:                  *tr.RandUint64(),                           // uint64
		Extra:                 tr.RandBytes(tr.RandIntInRange(128, 1024)), // []byte
		MixDigest:             tr.RandHash(),                              // libcommon.Hash
		Nonce:                 BlockNonce(tr.RandBytes(8)),                // BlockNonce
		BaseFee:               tr.RandBig(),                               // *big.Int
		WithdrawalsHash:       &wHash,                                     // *libcommon.Hash
		BlobGasUsed:           tr.RandUint64(),                            // *uint64
		ExcessBlobGas:         tr.RandUint64(),                            // *uint64
		ParentBeaconBlockRoot: &pHash,                                     //*libcommon.Hash
	}
}

func (tr *TRand) RandAccessTuple() types2.AccessTuple {
	n := tr.RandIntInRange(1, 5)
	sk := make([]libcommon.Hash, n)
	for i := 0; i < n; i++ {
		sk[i] = tr.RandHash()
	}
	return types2.AccessTuple{
		Address:     tr.RandAddress(),
		StorageKeys: sk,
	}
}

func (tr *TRand) RandAccessList(size int) types2.AccessList {
	al := make([]types2.AccessTuple, size)
	for i := 0; i < size; i++ {
		al[i] = tr.RandAccessTuple()
	}
	return al
}

func (tr *TRand) RandAuthorizations(size int) []Authorization {
	auths := make([]Authorization, size)
	for i := 0; i < size; i++ {
		auths[i] = Authorization{
			ChainID: uint256.NewInt(*tr.RandUint64()),
			Address: tr.RandAddress(),
			Nonce:   *tr.RandUint64(),
			V:       *uint256.NewInt(*tr.RandUint64()),
			R:       *uint256.NewInt(*tr.RandUint64()),
			S:       *uint256.NewInt(*tr.RandUint64()),
		}
	}
	return auths
}

func (tr *TRand) RandTransaction() Transaction {
	txType := tr.RandIntInRange(0, 5) // LegacyTxType, AccessListTxType, DynamicFeeTxType, BlobTxType, SetCodeTxType
	to := tr.RandAddress()
	commonTx := CommonTx{
		Nonce: *tr.RandUint64(),
		Gas:   *tr.RandUint64(),
		To:    &to,
		Value: uint256.NewInt(*tr.RandUint64()), // wei amount
		Data:  tr.RandBytes(tr.RandIntInRange(128, 1024)),
		V:     *uint256.NewInt(*tr.RandUint64()),
		R:     *uint256.NewInt(*tr.RandUint64()),
		S:     *uint256.NewInt(*tr.RandUint64()),
	}
	switch txType {
	case LegacyTxType:
		return &LegacyTx{
			CommonTx: commonTx, //nolint
			GasPrice: uint256.NewInt(*tr.RandUint64()),
		}
	case AccessListTxType:
		return &AccessListTx{
			LegacyTx: LegacyTx{
				CommonTx: commonTx, //nolint
				GasPrice: uint256.NewInt(*tr.RandUint64()),
			},
			ChainID:    uint256.NewInt(*tr.RandUint64()),
			AccessList: tr.RandAccessList(tr.RandIntInRange(1, 5)),
		}
	case DynamicFeeTxType:
		return &DynamicFeeTransaction{
			CommonTx:   commonTx, //nolint
			ChainID:    uint256.NewInt(*tr.RandUint64()),
			Tip:        uint256.NewInt(*tr.RandUint64()),
			FeeCap:     uint256.NewInt(*tr.RandUint64()),
			AccessList: tr.RandAccessList(tr.RandIntInRange(1, 5)),
		}
	case BlobTxType:
		r := *tr.RandUint64()
		return &BlobTx{
			DynamicFeeTransaction: DynamicFeeTransaction{
				CommonTx:   commonTx, //nolint
				ChainID:    uint256.NewInt(*tr.RandUint64()),
				Tip:        uint256.NewInt(*tr.RandUint64()),
				FeeCap:     uint256.NewInt(*tr.RandUint64()),
				AccessList: tr.RandAccessList(tr.RandIntInRange(1, 5)),
			},
			MaxFeePerBlobGas:    uint256.NewInt(r),
			BlobVersionedHashes: tr.RandHashes(tr.RandIntInRange(1, 2)),
		}
	case SetCodeTxType:
		return &SetCodeTransaction{
			DynamicFeeTransaction: DynamicFeeTransaction{
				CommonTx:   commonTx, //nolint
				ChainID:    uint256.NewInt(*tr.RandUint64()),
				Tip:        uint256.NewInt(*tr.RandUint64()),
				FeeCap:     uint256.NewInt(*tr.RandUint64()),
				AccessList: tr.RandAccessList(tr.RandIntInRange(1, 5)),
			},
			Authorizations: tr.RandAuthorizations(tr.RandIntInRange(0, 5)),
		}
	default:
		fmt.Printf("unexpected txType %v", txType)
		panic("unexpected txType")
	}
}

func (tr *TRand) RandHashes(size int) []libcommon.Hash {
	hashes := make([]libcommon.Hash, size)
	for i := 0; i < size; i++ {
		hashes[i] = tr.RandHash()
	}
	return hashes
}

func (tr *TRand) RandTransactions(size int) []Transaction {
	txns := make([]Transaction, size)
	for i := 0; i < size; i++ {
		txns[i] = tr.RandTransaction()
	}
	return txns
}

func (tr *TRand) RandRawTransactions(size int) [][]byte {
	txns := make([][]byte, size)
	for i := 0; i < size; i++ {
		txns[i] = tr.RandBytes(tr.RandIntInRange(1, 1023))
	}
	return txns
}

func (tr *TRand) RandHeaders(size int) []*Header {
	uncles := make([]*Header, size)
	for i := 0; i < size; i++ {
		uncles[i] = tr.RandHeader()
	}
	return uncles
}

func (tr *TRand) RandWithdrawals(size int) []*Withdrawal {
	withdrawals := make([]*Withdrawal, size)
	for i := 0; i < size; i++ {
		withdrawals[i] = tr.RandWithdrawal()
	}
	return withdrawals
}

func (tr *TRand) RandRawBody() *RawBody {
	return &RawBody{
		Transactions: tr.RandRawTransactions(tr.RandIntInRange(1, 6)),
		Uncles:       tr.RandHeaders(tr.RandIntInRange(1, 6)),
		Withdrawals:  tr.RandWithdrawals(tr.RandIntInRange(1, 6)),
	}
}

func (tr *TRand) RandRawBlock(setNil bool) *RawBlock {
	if setNil {
		return &RawBlock{
			Header: tr.RandHeader(),
			Body: &RawBody{
				Uncles:      nil,
				Withdrawals: nil,
			},
		}
	}

	return &RawBlock{
		Header: tr.RandHeader(),
		Body:   tr.RandRawBody(),
	}
}

func (tr *TRand) RandBody() *Body {
	return &Body{
		Transactions: tr.RandTransactions(tr.RandIntInRange(1, 6)),
		Uncles:       tr.RandHeaders(tr.RandIntInRange(1, 6)),
		Withdrawals:  tr.RandWithdrawals(tr.RandIntInRange(1, 6)),
	}
}

func (tr *TRand) RandLog() *Log {
	return &Log{
		Address: tr.RandAddress(),
		Topics:  tr.RandHashes(tr.RandIntInRange(1, 5)),
		Data:    tr.RandBytes(tr.RandIntInRange(32, 1024)),
	}
}

func isEqualBytes(a, b []byte) bool {
	for i := range a {
		if a[i] != b[i] {
			fmt.Printf("%v != %v at %v", a[i], b[i], i)
			return false
		}
	}
	return true
}

func check(t *testing.T, f string, want, got interface{}) {
	if !reflect.DeepEqual(want, got) {
		t.Errorf("%s mismatch: want %v, got %v", f, want, got)
	}
}

func checkHeaders(t *testing.T, a, b *Header) {
	check(t, "Header.ParentHash", a.ParentHash, b.ParentHash)
	check(t, "Header.UncleHash", a.UncleHash, b.UncleHash)
	check(t, "Header.Coinbase", a.Coinbase, b.Coinbase)
	check(t, "Header.Root", a.Root, b.Root)
	check(t, "Header.TxHash", a.TxHash, b.TxHash)
	check(t, "Header.ReceiptHash", a.ReceiptHash, b.ReceiptHash)
	check(t, "Header.Bloom", a.Bloom, b.Bloom)
	check(t, "Header.Difficulty", a.Difficulty, b.Difficulty)
	check(t, "Header.Number", a.Number, b.Number)
	check(t, "Header.GasLimit", a.GasLimit, b.GasLimit)
	check(t, "Header.GasUsed", a.GasUsed, b.GasUsed)
	check(t, "Header.Time", a.Time, b.Time)
	check(t, "Header.Extra", a.Extra, b.Extra)
	check(t, "Header.MixDigest", a.MixDigest, b.MixDigest)
	check(t, "Header.Nonce", a.Nonce, b.Nonce)
	check(t, "Header.BaseFee", a.BaseFee, b.BaseFee)
	check(t, "Header.WithdrawalsHash", a.WithdrawalsHash, b.WithdrawalsHash)
	check(t, "Header.BlobGasUsed", a.BlobGasUsed, b.BlobGasUsed)
	check(t, "Header.ExcessBlobGas", a.ExcessBlobGas, b.ExcessBlobGas)
	check(t, "Header.ParentBeaconBlockRoot", a.ParentBeaconBlockRoot, b.ParentBeaconBlockRoot)
}

func checkWithdrawals(t *testing.T, a, b *Withdrawal) {
	check(t, "Withdrawal.Index", a.Index, b.Index)
	check(t, "Withdrawal.Validator", a.Validator, b.Validator)
	check(t, "Withdrawal.Address", a.Address, b.Address)
	check(t, "Withdrawal.Amount", a.Amount, b.Amount)
}

func compareTransactions(t *testing.T, a, b Transaction) {
	v1, r1, s1 := a.RawSignatureValues()
	v2, r2, s2 := b.RawSignatureValues()
	check(t, "Tx.Type", a.Type(), b.Type())
	check(t, "Tx.GetChainID", a.GetChainID(), b.GetChainID())
	check(t, "Tx.GetNonce", a.GetNonce(), b.GetNonce())
	check(t, "Tx.GetPrice", a.GetPrice(), b.GetPrice())
	check(t, "Tx.GetTip", a.GetTip(), b.GetTip())
	check(t, "Tx.GetFeeCap", a.GetFeeCap(), b.GetFeeCap())
	check(t, "Tx.GetBlobHashes", a.GetBlobHashes(), b.GetBlobHashes())
	check(t, "Tx.GetGas", a.GetGas(), b.GetGas())
	check(t, "Tx.GetBlobGas", a.GetBlobGas(), b.GetBlobGas())
	check(t, "Tx.GetValue", a.GetValue(), b.GetValue())
	check(t, "Tx.GetTo", a.GetTo(), b.GetTo())
	check(t, "Tx.GetData", a.GetData(), b.GetData())
	check(t, "Tx.GetAccessList", a.GetAccessList(), b.GetAccessList())
	check(t, "Tx.V", v1, v2)
	check(t, "Tx.R", r1, r2)
	check(t, "Tx.S", s1, s2)
}

func compareHeaders(t *testing.T, a, b []*Header) error {
	auLen, buLen := len(a), len(b)
	if auLen != buLen {
		return fmt.Errorf("uncles len mismatch: expected: %v, got: %v", auLen, buLen)
	}

	for i := 0; i < auLen; i++ {
		checkHeaders(t, a[i], b[i])
	}
	return nil
}

func compareWithdrawals(t *testing.T, a, b []*Withdrawal) error {
	awLen, bwLen := len(a), len(b)
	if awLen != bwLen {
		return fmt.Errorf("withdrawals len mismatch: expected: %v, got: %v", awLen, bwLen)
	}

	for i := 0; i < awLen; i++ {
		checkWithdrawals(t, a[i], b[i])
	}
	return nil
}

func compareRawBodies(t *testing.T, a, b *RawBody) error {

	atLen, btLen := len(a.Transactions), len(b.Transactions)
	if atLen != btLen {
		return fmt.Errorf("transactions len mismatch: expected: %v, got: %v", atLen, btLen)
	}

	for i := 0; i < atLen; i++ {
		if !isEqualBytes(a.Transactions[i], b.Transactions[i]) {
			return fmt.Errorf("byte transactions are not equal")
		}
	}

	compareHeaders(t, a.Uncles, b.Uncles)
	compareWithdrawals(t, a.Withdrawals, b.Withdrawals)
	return nil
}

func compareBodies(t *testing.T, a, b *Body) error {

	atLen, btLen := len(a.Transactions), len(b.Transactions)
	if atLen != btLen {
		return fmt.Errorf("txns len mismatch: expected: %v, got: %v", atLen, btLen)
	}

	for i := 0; i < atLen; i++ {
		compareTransactions(t, a.Transactions[i], b.Transactions[i])
	}

	compareHeaders(t, a.Uncles, b.Uncles)
	compareWithdrawals(t, a.Withdrawals, b.Withdrawals)

	return nil
}

func compareLogs(t *testing.T, a, b *Log) error {

	for i := 0; i < 20; i++ {
		if a.Address[i] != b.Address[i] {
			return fmt.Errorf("addresses mismatch at idx=%v: %v != %v", i, a.Address[i], b.Address[i])
		}
	}

	atLen, btLen := len(a.Topics), len(b.Topics)
	if atLen != btLen {
		return fmt.Errorf("topics len mismatch: expected: %v, got: %v", atLen, btLen)
	}

	for i := 0; i < atLen; i++ {
		if len(a.Topics[i]) != 32 || len(b.Topics[i]) != 32 {
			return fmt.Errorf("topic len != 32: topic idx=%v,  len(a.Topics[i])=%v, len(b.Topics[i])=%v", i, len(a.Topics[i]), len(b.Topics[i]))
		}

		for j := 0; j < 32; j++ {
			if a.Topics[i][j] != b.Topics[i][j] {
				return fmt.Errorf("topic mismatch at idx: %v, a.Topics[i]=0x%x, b.Topics[i]=0x%x", i, a.Topics[i], b.Topics[i])
			}
		}
	}

	adLen, bdLen := len(a.Data), len(b.Data)
	if adLen != bdLen {
		return fmt.Errorf("data len mismatch: expected: %v, got: %v", adLen, bdLen)
	}

	for i := 0; i < adLen; i++ {
		if a.Data[i] != b.Data[i] {
			return fmt.Errorf("data len mismatch: expected: %v, got: %v", a.Data, b.Data)
		}
	}

	return nil
}

// func TestRawBodyEncodeDecodeRLP(t *testing.T) {
// 	tr := NewTRand()
// 	var buf bytes.Buffer
// 	for i := 0; i < RUNS; i++ {
// 		enc := tr.RandRawBody()
// 		buf.Reset()
// 		if err := enc.EncodeRLP(&buf); err != nil {
// 			t.Errorf("error: RawBody.EncodeRLP(): %v", err)
// 		}

// 		s := rlp.NewStream(bytes.NewReader(buf.Bytes()), 0)

// 		dec := &RawBody{}
// 		if err := dec.DecodeRLP(s); err != nil {
// 			t.Errorf("error: RawBody.DecodeRLP(): %v", err)
// 			panic(err)
// 		}

// 		if err := compareRawBodies(t, enc, dec); err != nil {
// 			t.Errorf("error: compareRawBodies: %v", err)
// 		}
// 	}
// }

func TestBodyEncodeDecodeRLP(t *testing.T) {
	tr := NewTRand()
	var buf bytes.Buffer
	for i := 0; i < RUNS; i++ {
		enc := tr.RandBody()
		buf.Reset()
		if err := enc.EncodeRLP(&buf); err != nil {
			t.Errorf("error: RawBody.EncodeRLP(): %v", err)
		}

		s := rlp.NewStream(bytes.NewReader(buf.Bytes()), 0)
		dec := &Body{}
		if err := dec.DecodeRLP(s); err != nil {
			t.Errorf("error: RawBody.DecodeRLP(): %v", err)
			panic(err)
		}

		if err := compareBodies(t, enc, dec); err != nil {
			t.Errorf("error: compareBodies: %v", err)
		}
	}
}

func TestLogEncodeDecodeRLP(t *testing.T) {
	tr := NewTRand()
	var buf bytes.Buffer
	for i := 0; i < RUNS; i++ {
		enc := tr.RandLog()
		buf.Reset()
		if err := enc.encodeRLP(&buf); err != nil {
			t.Errorf("error: Log.EncodeRLP(): %v", err)
		}
		fmt.Println(buf.Bytes())
		s := rlp.NewStream(bytes.NewReader(buf.Bytes()), 0)
		dec := &Log{}
		if err := dec.decodeRLP(s); err != nil {
			t.Errorf("error: Log.DecodeRLP(): %v", err)
			panic(err)
		}

		if err := compareLogs(t, enc, dec); err != nil {
			t.Errorf("error: compareLogs: %v", err)
		}
	}
}

var _log = Log{
	Address: libcommon.Address{0, 228, 187, 88, 112, 28, 134, 47, 206, 54, 177, 18, 153, 224, 225, 161, 117, 171, 179, 19},
	Topics: []libcommon.Hash{
		{138, 91, 92, 35, 250, 86, 72, 255, 246, 187, 191, 125, 101, 9, 197, 162, 185, 195, 68, 158, 58, 117, 71, 235, 223, 42, 164, 228, 186, 1, 191, 251},
		{99, 152, 198, 160, 131, 168, 53, 118, 35, 56, 133, 204, 248, 97, 69, 115, 118, 30, 54, 137, 245, 42, 250, 247, 106, 170, 220, 153, 124, 196, 252, 141},
		{147, 75, 108, 218, 217, 46, 137, 51, 47, 101, 196, 161, 156, 205, 72, 108, 31, 140, 141, 208, 80, 139, 198, 240, 99, 63, 1, 231, 63, 131, 26, 118},
	},
	Data: []byte{125, 55, 122, 143, 112, 122, 217, 166, 140, 91, 233, 185, 152, 62, 232, 17, 13, 108, 103, 194, 180, 0, 29, 122, 165, 63, 85, 238, 28, 208, 38, 129, 133, 196, 209, 123, 20, 143, 158, 215, 106, 171, 222, 72, 123, 51, 200, 92, 7, 78, 210, 122, 7, 109, 118, 192, 243, 1, 135, 163, 156, 16, 107, 198, 70, 12, 45, 231, 216, 85, 34, 126, 245, 169, 122, 29, 21, 171, 175, 174, 96, 38, 83, 77, 245, 99, 63, 127, 46, 132, 82, 44, 98, 123, 165, 137, 125, 195, 77, 117, 120, 173, 165, 236, 194, 138, 130, 198, 141, 8, 119, 69, 109, 50, 16, 203, 193, 128, 132, 167, 237, 68, 67, 190},
}

func BenchmarkLogEncodeRLP(b *testing.B) {
	var buf bytes.Buffer
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		buf.Reset()
		_log.encodeRLP(&buf)
	}
}

func BenchmarkLogEncodeRLPgen(b *testing.B) {
	var buf bytes.Buffer
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		buf.Reset()
		_log.EncodeRLP(&buf)
	}
}

var encodedLog = []byte{249, 2, 97, 148, 154, 166, 225, 30, 206, 3, 234, 61, 197, 160, 107, 76, 95, 156, 106, 148, 72, 45, 175, 210, 248, 132, 160, 211, 227, 100, 194, 190, 68, 202, 30, 106, 6, 123, 225, 197, 92, 251, 3, 74, 16, 233, 35, 143, 75, 212, 73, 86, 156, 129, 21, 10, 70, 58, 23, 160, 89, 176, 94, 77, 38, 239, 134, 122, 59, 101, 127, 139, 153, 80, 196, 131, 39, 16, 136, 83, 19, 175, 31, 14, 208, 219, 177, 226, 160, 10, 144, 6, 160, 196, 194, 215, 107, 179, 109, 15, 82, 91, 238, 25, 165, 100, 174, 7, 176, 152, 39, 137, 198, 218, 82, 147, 195, 173, 58, 129, 103, 75, 186, 213, 110, 160, 6, 121, 243, 198, 200, 74, 146, 74, 220, 51, 130, 99, 8, 210, 135, 228, 100, 227, 12, 71, 55, 30, 49, 31, 61, 235, 46, 197, 87, 97, 16, 62, 185, 1, 195, 214, 220, 126, 230, 206, 197, 38, 44, 18, 227, 73, 135, 153, 38, 112, 26, 148, 194, 9, 155, 91, 208, 101, 198, 146, 37, 243, 159, 159, 143, 245, 170, 140, 193, 208, 85, 237, 179, 75, 101, 252, 235, 149, 172, 237, 84, 133, 145, 75, 5, 149, 66, 98, 205, 89, 249, 180, 63, 206, 185, 44, 196, 248, 141, 152, 36, 133, 99, 50, 119, 224, 186, 179, 180, 21, 154, 245, 183, 110, 197, 130, 207, 46, 192, 190, 12, 39, 113, 71, 21, 150, 220, 250, 87, 4, 95, 135, 154, 105, 60, 107, 172, 137, 129, 185, 42, 237, 229, 152, 159, 195, 99, 167, 193, 25, 34, 115, 166, 160, 45, 144, 172, 70, 186, 241, 95, 100, 56, 159, 78, 173, 250, 249, 219, 114, 102, 129, 195, 191, 104, 207, 19, 123, 166, 203, 137, 141, 234, 255, 33, 174, 12, 1, 163, 204, 114, 141, 85, 34, 8, 89, 172, 68, 230, 7, 225, 9, 240, 209, 159, 98, 198, 240, 235, 2, 242, 232, 163, 161, 183, 23, 75, 86, 231, 214, 149, 247, 230, 142, 212, 34, 89, 136, 111, 182, 125, 2, 55, 129, 191, 158, 229, 50, 228, 146, 36, 182, 195, 96, 85, 70, 225, 72, 8, 108, 7, 203, 163, 132, 222, 247, 186, 222, 28, 182, 156, 132, 254, 8, 45, 3, 229, 47, 36, 104, 118, 188, 135, 90, 46, 147, 195, 19, 233, 85, 82, 197, 147, 161, 22, 192, 88, 119, 184, 246, 67, 146, 3, 45, 104, 127, 51, 102, 90, 217, 202, 63, 17, 0, 253, 156, 220, 215, 6, 56, 171, 165, 148, 150, 50, 5, 205, 165, 117, 133, 60, 99, 174, 166, 108, 252, 21, 181, 98, 20, 231, 182, 191, 187, 160, 218, 70, 75, 18, 29, 200, 246, 124, 50, 52, 17, 80, 15, 194, 12, 104, 173, 175, 41, 233, 154, 24, 38, 73, 151, 108, 241, 239, 93, 134, 127, 157, 170, 72, 7, 55, 215, 147, 33, 196, 142, 219, 15, 164, 91, 212, 149, 212, 87, 19, 30, 84, 14, 179, 231, 100, 23, 214, 196, 10, 169, 138, 71, 246, 188, 156, 150, 25, 200, 84, 22, 247, 66, 46, 113, 144, 30, 224, 57, 54, 176, 67, 36, 115, 53, 145, 133, 1, 165, 226, 129, 176, 167, 217, 181, 161, 77, 231, 238, 131, 250, 118, 93, 248, 83, 210, 60, 95, 57, 123, 10, 2, 145, 27, 44, 54, 133, 185, 57, 137, 3, 194, 147, 67, 76, 71, 94, 174, 137, 115, 26, 249, 93, 50, 241, 241, 114, 134, 238, 205, 193, 65, 160, 250, 24, 245, 140, 160, 83, 183, 234}

func BenchmarkLogDecodeRLP(b *testing.B) {
	s := rlp.NewStream(bytes.NewReader(encodedLog), 0)
	dec := &Log{}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		dec.decodeRLP(s)
	}
}

func BenchmarkLogDecodeRLPgen(b *testing.B) {
	s := rlp.NewStream(bytes.NewReader(encodedLog), 0)
	dec := &Log{}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		dec.DecodeRLP(s)
	}
}

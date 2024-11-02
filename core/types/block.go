// Copyright 2014 The go-ethereum Authors
// (original work)
// Copyright 2024 The Erigon Authors
// (modifications)
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

// Package types contains data types related to Ethereum consensus.
package types

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"sync/atomic"

	"github.com/gballet/go-verkle"

	libcommon "github.com/erigontech/erigon-lib/common"
	"github.com/erigontech/erigon-lib/common/hexutil"
	"github.com/erigontech/erigon-lib/common/hexutility"
	rlp2 "github.com/erigontech/erigon-lib/rlp"
	"github.com/erigontech/erigon/common"
	"github.com/erigontech/erigon/rlp"
)

var (
	EmptyRootHash     = libcommon.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
	EmptyRequestsHash = libcommon.HexToHash("6036c41849da9c076ed79654d434017387a88fb833c2856b32e18218b3341c5f")
	EmptyUncleHash    = rlpHash([]*Header(nil))

	ExtraVanityLength = 32 // Fixed number of extra-data prefix bytes reserved for signer vanity
	ExtraSealLength   = 65 // Fixed number of extra-data suffix bytes reserved for signer seal
)

// A BlockNonce is a 64-bit hash which proves (combined with the
// mix-hash) that a sufficient amount of computation has been carried
// out on a block.
type BlockNonce [8]byte

// EncodeNonce converts the given integer to a block nonce.
func EncodeNonce(i uint64) BlockNonce {
	var n BlockNonce
	binary.BigEndian.PutUint64(n[:], i)
	return n
}

// Uint64 returns the integer value of a block nonce.
func (n BlockNonce) Uint64() uint64 {
	return binary.BigEndian.Uint64(n[:])
}

// MarshalText encodes n as a hex string with 0x prefix.
func (n BlockNonce) MarshalText() ([]byte, error) {
	return hexutility.Bytes(n[:]).MarshalText()
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (n *BlockNonce) UnmarshalText(input []byte) error {
	return hexutility.UnmarshalFixedText("BlockNonce", input, n[:])
}

//()go:generate gencodec -type Header -field-override headerMarshaling -out gen_header_json.go

// Header represents a block header in the Ethereum blockchain.
// DESCRIBED: docs/programmers_guide/guide.md#organising-ethereum-state-into-a-merkle-tree
type Header struct {
	ParentHash  libcommon.Hash    `json:"parentHash"       gencodec:"required"`
	UncleHash   libcommon.Hash    `json:"sha3Uncles"       gencodec:"required"`
	Coinbase    libcommon.Address `json:"miner"`
	Root        libcommon.Hash    `json:"stateRoot"        gencodec:"required"`
	TxHash      libcommon.Hash    `json:"transactionsRoot" gencodec:"required"`
	ReceiptHash libcommon.Hash    `json:"receiptsRoot"     gencodec:"required"`
	Bloom       Bloom             `json:"logsBloom"        gencodec:"required"`
	Difficulty  *big.Int          `json:"difficulty"       gencodec:"required"`
	Number      *big.Int          `json:"number"           gencodec:"required"`
	GasLimit    uint64            `json:"gasLimit"         gencodec:"required"`
	GasUsed     uint64            `json:"gasUsed"          gencodec:"required"`
	Time        uint64            `json:"timestamp"        gencodec:"required"`
	Extra       []byte            `json:"extraData"        gencodec:"required"`
	MixDigest   libcommon.Hash    `json:"mixHash"` // prevRandao after EIP-4399
	Nonce       BlockNonce        `json:"nonce"`
	// AuRa extensions (alternative to MixDigest & Nonce)
	AuRaStep uint64
	AuRaSeal []byte

	BaseFee         *big.Int        `json:"baseFeePerGas"`   // EIP-1559
	WithdrawalsHash *libcommon.Hash `json:"withdrawalsRoot"` // EIP-4895

	// BlobGasUsed & ExcessBlobGas were added by EIP-4844 and are ignored in legacy headers.
	BlobGasUsed   *uint64 `json:"blobGasUsed"`
	ExcessBlobGas *uint64 `json:"excessBlobGas"`

	ParentBeaconBlockRoot *libcommon.Hash `json:"parentBeaconBlockRoot"` // EIP-4788

	RequestsHash *libcommon.Hash `json:"requestsHash"` // EIP-7685

	// The verkle proof is ignored in legacy headers
	Verkle        bool
	VerkleProof   []byte
	VerkleKeyVals []verkle.KeyValuePair

	// by default all headers are immutable
	// but assembling/mining may use `NewEmptyHeaderForAssembling` to create temporary mutable Header object
	// then pass it to `block.WithSeal(header)` - to produce new block with immutable `Header`
	mutable bool
	hash    atomic.Pointer[libcommon.Hash]
}

// NewEmptyHeaderForAssembling - returns mutable header object - for assembling/sealing/etc...
// when sealing done - `block.WithSeal(header)` called - which producing new block with immutable `Header`
// by default all headers are immutable
func NewEmptyHeaderForAssembling() *Header {
	return &Header{mutable: true}
}

// field type overrides for gencodec
type headerMarshaling struct {
	Difficulty    *hexutil.Big
	Number        *hexutil.Big
	GasLimit      hexutil.Uint64
	GasUsed       hexutil.Uint64
	Time          hexutil.Uint64
	Extra         hexutility.Bytes
	BaseFee       *hexutil.Big
	BlobGasUsed   *hexutil.Uint64
	ExcessBlobGas *hexutil.Uint64
	Hash          libcommon.Hash `json:"hash"` // adds call to Hash() in MarshalJSON
}

// Hash returns the block hash of the header, which is simply the keccak256 hash of its
// RLP encoding.
func (h *Header) Hash() (hash libcommon.Hash) {
	if !h.mutable {
		if hash := h.hash.Load(); hash != nil {
			return *hash
		}
	}
	hash = rlpHash(h)
	if !h.mutable {
		h.hash.Store(&hash)
	}
	return hash
}

var headerSize = common.StorageSize(reflect.TypeOf(Header{}).Size())

// Size returns the approximate memory used by all internal contents. It is used
// to approximate and limit the memory consumption of various caches.
func (h *Header) Size() common.StorageSize {
	s := headerSize
	s += common.StorageSize(len(h.Extra) + libcommon.BitLenToByteLen(h.Difficulty.BitLen()) + libcommon.BitLenToByteLen(h.Number.BitLen()))
	if h.BaseFee != nil {
		s += common.StorageSize(libcommon.BitLenToByteLen(h.BaseFee.BitLen()))
	}
	if h.WithdrawalsHash != nil {
		s += common.StorageSize(32)
	}
	if h.BlobGasUsed != nil {
		s += common.StorageSize(8)
	}
	if h.ExcessBlobGas != nil {
		s += common.StorageSize(8)
	}
	if h.ParentBeaconBlockRoot != nil {
		s += common.StorageSize(32)
	}
	if h.RequestsHash != nil {
		s += common.StorageSize(32)
	}
	return s
}

// SanityCheck checks a few basic things -- these checks are way beyond what
// any 'sane' production values should hold, and can mainly be used to prevent
// that the unbounded fields are stuffed with junk data to add processing
// overhead
func (h *Header) SanityCheck() error {
	if h.Number != nil && !h.Number.IsUint64() {
		return fmt.Errorf("too large block number: bitlen %d", h.Number.BitLen())
	}
	if h.Difficulty != nil {
		if diffLen := h.Difficulty.BitLen(); diffLen > 192 {
			return fmt.Errorf("too large block difficulty: bitlen %d", diffLen)
		}
	}
	if eLen := len(h.Extra); eLen > 100*1024 {
		return fmt.Errorf("too large block extradata: size %d", eLen)
	}
	if h.BaseFee != nil {
		if bfLen := h.BaseFee.BitLen(); bfLen > 256 {
			return fmt.Errorf("too large base fee: bitlen %d", bfLen)
		}
	}

	return nil
}

// Body is a simple (mutable, non-safe) data container for storing and moving
// a block's data contents (transactions and uncles) together.
type Body struct {
	Transactions []Transaction
	Uncles       []*Header
	Withdrawals  []*Withdrawal
}

// RawBody is semi-parsed variant of Body, where transactions are still unparsed RLP strings
// It is useful in the situations when actual transaction context is not important, for example
// when downloading Block bodies from other peers or serving them to other peers
type RawBody struct {
	Transactions [][]byte
	Uncles       []*Header
	Withdrawals  []*Withdrawal
}

// BaseTxnID represents internal auto-incremented transaction number in block, may be different across the nodes
// e.g. block has 3 transactions, then txAmount = 3+2/*systemTx*/ = 5 therefore:
//
//	0 - base tx/systemBegin
//	1 - tx0
//	2 - tx1
//	3 - tx2
//	4 - systemEnd
//
//	System transactions are used to write history of state changes done by consensus (not by eth-transactions) - for example "miner rewards"
type BaseTxnID uint64

// TxCountToTxAmount converts number of transactions in block to TxAmount
func TxCountToTxAmount(txsLen int) uint32 {
	return uint32(txsLen + 2)
}

func (b BaseTxnID) U64() uint64 { return uint64(b) }

func (b BaseTxnID) Bytes() []byte { return hexutility.EncodeTs(uint64(b)) }

// First non-system txn number in block
// as if baseTxnID is first original transaction in block
func (b BaseTxnID) First() uint64 { return uint64(b + 1) }

// At returns txn number at block position `ti`.
func (b BaseTxnID) At(ti int) uint64 { return b.First() + uint64(ti) }

// FirstSystemTx returns first system txn number in block
func (b BaseTxnID) FirstSystemTx() BaseTxnID { return b }

// LastSystemTx returns last system txn number in block. result+1 will be baseID of next block a.k.a. beginning system txn number
// Supposed that txAmount includes 2 system txns.
func (b BaseTxnID) LastSystemTx(txAmount uint32) uint64 { return b.U64() + uint64(txAmount) - 1 }

type BodyForStorage struct {
	BaseTxnID   BaseTxnID
	TxCount     uint32
	Uncles      []*Header
	Withdrawals []*Withdrawal
}

// Alternative representation of the Block.
type RawBlock struct {
	Header *Header
	Body   *RawBody
}

func (r RawBlock) AsBlock() (*Block, error) {
	b := &Block{header: r.Header}
	b.uncles = r.Body.Uncles
	b.withdrawals = r.Body.Withdrawals

	txs := make([]Transaction, len(r.Body.Transactions))
	for i, txn := range r.Body.Transactions {
		var err error
		if txs[i], err = DecodeTransaction(txn); err != nil {
			return nil, err
		}
	}
	b.transactions = txs

	return b, nil
}

// Block represents an entire block in the Ethereum blockchain.
type Block struct {
	header       *Header
	uncles       []*Header
	transactions Transactions
	withdrawals  []*Withdrawal

	// caches
	size atomic.Uint64
}

// Copy transaction senders from body into the transactions
func (b *Body) SendersToTxs(senders []libcommon.Address) {
	if senders == nil {
		return
	}
	for i, txn := range b.Transactions {
		txn.SetSender(senders[i])
	}
}

// Copy transaction senders from transactions to the body
func (b *Body) SendersFromTxs() []libcommon.Address {
	senders := make([]libcommon.Address, len(b.Transactions))
	for i, txn := range b.Transactions {
		if sender, ok := txn.GetSender(); ok {
			senders[i] = sender
		}
	}
	return senders
}

// NewBlock creates a new block. The input data is copied,
// changes to header and to the field values will not affect the block.
//
// The values of TxHash, UncleHash, ReceiptHash, Bloom, and WithdrawalHash
// in the header are ignored and set to the values derived from
// the given txs, uncles, receipts, and withdrawals.
func NewBlock(header *Header, txs []Transaction, uncles []*Header, receipts []*Receipt, withdrawals []*Withdrawal) *Block {
	b := &Block{header: CopyHeader(header)}

	// TODO: panic if len(txs) != len(receipts)
	if len(txs) == 0 {
		b.header.TxHash = EmptyRootHash
	} else {
		b.header.TxHash = DeriveSha(Transactions(txs))
		b.transactions = make(Transactions, len(txs))
		copy(b.transactions, txs)
	}

	if len(receipts) == 0 {
		b.header.ReceiptHash = EmptyRootHash
		b.header.Bloom = Bloom{}
	} else {
		b.header.ReceiptHash = DeriveSha(Receipts(receipts))
		b.header.Bloom = CreateBloom(receipts)
	}

	if len(uncles) == 0 {
		b.header.UncleHash = EmptyUncleHash
	} else {
		b.header.UncleHash = CalcUncleHash(uncles)
		b.uncles = make([]*Header, len(uncles))
		for i := range uncles {
			b.uncles[i] = CopyHeader(uncles[i])
		}
	}

	if withdrawals == nil {
		b.header.WithdrawalsHash = nil
	} else if len(withdrawals) == 0 {
		b.header.WithdrawalsHash = &EmptyRootHash
		b.withdrawals = make(Withdrawals, len(withdrawals))
	} else {
		h := DeriveSha(Withdrawals(withdrawals))
		b.header.WithdrawalsHash = &h
		b.withdrawals = make(Withdrawals, len(withdrawals))
		for i, w := range withdrawals {
			wCopy := *w
			b.withdrawals[i] = &wCopy
		}
	}

	b.header.ParentBeaconBlockRoot = header.ParentBeaconBlockRoot
	b.header.mutable = false //Force immutability of block and header. Use `NewBlockForAsembling` if you need mutable block
	return b
}

// NewBlockForAsembling - creating new block - which allow mutation of fileds. Use it for block-assembly
func NewBlockForAsembling(header *Header, txs []Transaction, uncles []*Header, receipts []*Receipt, withdrawals []*Withdrawal) *Block {
	b := NewBlock(header, txs, uncles, receipts, withdrawals)
	b.header.mutable = true
	return b
}

// NewBlockFromStorage like NewBlock but used to create Block object when read it from DB
// in this case no reason to copy parts, or re-calculate headers fields - they are all stored in DB
func NewBlockFromStorage(hash libcommon.Hash, header *Header, txs []Transaction, uncles []*Header, withdrawals []*Withdrawal) *Block {
	header.hash.Store(&hash)
	b := &Block{header: header, transactions: txs, uncles: uncles, withdrawals: withdrawals}
	return b
}

// NewBlockWithHeader creates a block with the given header data. The
// header data is copied, changes to header and to the field values
// will not affect the block.
func NewBlockWithHeader(header *Header) *Block {
	return &Block{header: CopyHeader(header)}
}

// NewBlockFromNetwork like NewBlock but used to create Block object when assembled from devp2p network messages
// when there is no reason to copy parts, or re-calculate headers fields.
func NewBlockFromNetwork(header *Header, body *Body) *Block {
	return &Block{
		header:       header,
		transactions: body.Transactions,
		uncles:       body.Uncles,
		withdrawals:  body.Withdrawals,
	}
}

// CopyHeader creates a deep copy of a block header to prevent side effects from
// modifying a header variable.
func CopyHeader(h *Header) *Header {
	cpy := *h //nolint
	if cpy.Difficulty = new(big.Int); h.Difficulty != nil {
		cpy.Difficulty.Set(h.Difficulty)
	}
	if cpy.Number = new(big.Int); h.Number != nil {
		cpy.Number.Set(h.Number)
	}
	if h.BaseFee != nil {
		cpy.BaseFee = new(big.Int)
		cpy.BaseFee.Set(h.BaseFee)
	}
	if len(h.Extra) > 0 {
		cpy.Extra = make([]byte, len(h.Extra))
		copy(cpy.Extra, h.Extra)
	}
	if len(h.AuRaSeal) > 0 {
		cpy.AuRaSeal = make([]byte, len(h.AuRaSeal))
		copy(cpy.AuRaSeal, h.AuRaSeal)
	}
	if h.WithdrawalsHash != nil {
		cpy.WithdrawalsHash = new(libcommon.Hash)
		cpy.WithdrawalsHash.SetBytes(h.WithdrawalsHash.Bytes())
	}
	if h.BlobGasUsed != nil {
		blobGasUsed := *h.BlobGasUsed
		cpy.BlobGasUsed = &blobGasUsed
	}
	if h.ExcessBlobGas != nil {
		excessBlobGas := *h.ExcessBlobGas
		cpy.ExcessBlobGas = &excessBlobGas
	}
	if h.ParentBeaconBlockRoot != nil {
		cpy.ParentBeaconBlockRoot = new(libcommon.Hash)
		cpy.ParentBeaconBlockRoot.SetBytes(h.ParentBeaconBlockRoot.Bytes())
	}
	if h.RequestsHash != nil {
		cpy.RequestsHash = new(libcommon.Hash)
		cpy.RequestsHash.SetBytes(h.RequestsHash.Bytes())
	}
	cpy.mutable = h.mutable
	if hash := h.hash.Load(); hash != nil {
		hashCopy := *hash
		cpy.hash.Store(&hashCopy)
	}
	return &cpy
}

func (b *Block) Uncles() []*Header          { return b.uncles }
func (b *Block) Transactions() Transactions { return b.transactions }

func (b *Block) Transaction(hash libcommon.Hash) Transaction {
	for _, transaction := range b.transactions {
		if transaction.Hash() == hash {
			return transaction
		}
	}
	return nil
}

func (b *Block) Number() *big.Int     { return b.header.Number }
func (b *Block) GasLimit() uint64     { return b.header.GasLimit }
func (b *Block) GasUsed() uint64      { return b.header.GasUsed }
func (b *Block) Difficulty() *big.Int { return new(big.Int).Set(b.header.Difficulty) }
func (b *Block) Time() uint64         { return b.header.Time }

func (b *Block) NumberU64() uint64           { return b.header.Number.Uint64() }
func (b *Block) MixDigest() libcommon.Hash   { return b.header.MixDigest }
func (b *Block) Nonce() BlockNonce           { return b.header.Nonce }
func (b *Block) NonceU64() uint64            { return b.header.Nonce.Uint64() }
func (b *Block) Bloom() Bloom                { return b.header.Bloom }
func (b *Block) Coinbase() libcommon.Address { return b.header.Coinbase }
func (b *Block) Root() libcommon.Hash        { return b.header.Root }
func (b *Block) ParentHash() libcommon.Hash  { return b.header.ParentHash }
func (b *Block) TxHash() libcommon.Hash      { return b.header.TxHash }
func (b *Block) ReceiptHash() libcommon.Hash { return b.header.ReceiptHash }
func (b *Block) UncleHash() libcommon.Hash   { return b.header.UncleHash }
func (b *Block) Extra() []byte               { return libcommon.CopyBytes(b.header.Extra) }
func (b *Block) BaseFee() *big.Int {
	if b.header.BaseFee == nil {
		return nil
	}
	return new(big.Int).Set(b.header.BaseFee)
}
func (b *Block) WithdrawalsHash() *libcommon.Hash       { return b.header.WithdrawalsHash }
func (b *Block) Withdrawals() Withdrawals               { return b.withdrawals }
func (b *Block) ParentBeaconBlockRoot() *libcommon.Hash { return b.header.ParentBeaconBlockRoot }
func (b *Block) RequestsHash() *libcommon.Hash          { return b.header.RequestsHash }

// Header returns a deep-copy of the entire block header using CopyHeader()
func (b *Block) Header() *Header       { return CopyHeader(b.header) }
func (b *Block) HeaderNoCopy() *Header { return b.header }

// Body returns the non-header content of the block.
func (b *Block) Body() *Body {
	bd := &Body{Transactions: b.transactions, Uncles: b.uncles, Withdrawals: b.withdrawals}
	bd.SendersFromTxs()
	return bd
}
func (b *Block) SendersToTxs(senders []libcommon.Address) {
	if len(senders) == 0 {
		return
	}
	for i, txn := range b.transactions {
		txn.SetSender(senders[i])
	}
}

// RawBody creates a RawBody based on the block. It is not very efficient, so
// will probably be removed in favour of RawBlock. Also it panics
func (b *Block) RawBody() *RawBody {
	br := &RawBody{Transactions: make([][]byte, len(b.transactions)), Uncles: b.uncles, Withdrawals: b.withdrawals}
	for i, txn := range b.transactions {
		var err error
		br.Transactions[i], err = rlp.EncodeToBytes(txn)
		if err != nil {
			panic(err)
		}
	}
	return br
}

// RawBody creates a RawBody based on the body.
func (b *Body) RawBody() *RawBody {
	br := &RawBody{Transactions: make([][]byte, len(b.Transactions)), Uncles: b.Uncles, Withdrawals: b.Withdrawals}
	for i, txn := range b.Transactions {
		var err error
		br.Transactions[i], err = rlp.EncodeToBytes(txn)
		if err != nil {
			panic(err)
		}
	}
	return br
}

// Size returns the true RLP encoded storage size of the block, either by encoding
// and returning it, or returning a previously cached value.
func (b *Block) Size() common.StorageSize {
	if size := b.size.Load(); size > 0 {
		return common.StorageSize(size)
	}
	c := writeCounter(0)
	rlp.Encode(&c, b)
	b.size.Store(uint64(c))
	return common.StorageSize(c)
}

// SanityCheck can be used to prevent that unbounded fields are
// stuffed with junk data to add processing overhead
func (b *Block) SanityCheck() error {
	return b.header.SanityCheck()
}

// HashCheck checks that transactions, receipts, uncles, and withdrawals hashes are correct.
func (b *Block) HashCheck(fullCheck bool) error {
	if hash := DeriveSha(b.Transactions()); hash != b.TxHash() {
		return fmt.Errorf("block has invalid transaction hash: have %x, exp: %x", hash, b.TxHash())
	}

	if fullCheck {
		// execution-spec-tests contain such scenarios where block has an invalid tx, but receiptHash is default (=EmptyRootHash)
		// the test is to see if tx is rejected in EL, but in mock_sentry.go, we have HashCheck() before block execution.
		// Since we want the tx execution to happen, we skip it here and bypass this guard.
		if len(b.transactions) > 0 && b.ReceiptHash() == EmptyRootHash {
			return fmt.Errorf("block has empty receipt hash: %x but it includes %x transactions", b.ReceiptHash(), len(b.transactions))
		}
	}

	if len(b.transactions) == 0 && b.ReceiptHash() != EmptyRootHash {
		return fmt.Errorf("block has non-empty receipt hash: %x but no transactions", b.ReceiptHash())
	}

	if hash := CalcUncleHash(b.Uncles()); hash != b.UncleHash() {
		return fmt.Errorf("block has invalid uncle hash: have %x, exp: %x", hash, b.UncleHash())
	}

	if b.WithdrawalsHash() == nil {
		if b.Withdrawals() != nil {
			return errors.New("header missing WithdrawalsHash")
		}
		return nil
	}
	if b.Withdrawals() == nil {
		return errors.New("body missing Withdrawals")
	}

	if hash := DeriveSha(b.Withdrawals()); hash != *b.WithdrawalsHash() {
		return fmt.Errorf("block has invalid withdrawals hash: have %x, exp: %x", hash, b.WithdrawalsHash())
	}

	return nil
}

type writeCounter common.StorageSize

func (c *writeCounter) Write(b []byte) (int, error) {
	*c += writeCounter(len(b))
	return len(b), nil
}

func CalcUncleHash(uncles []*Header) libcommon.Hash {
	if len(uncles) == 0 {
		return EmptyUncleHash
	}
	return rlpHash(uncles)
}

func CopyTxs(in Transactions) Transactions {
	transactionsData, err := MarshalTransactionsBinary(in)
	if err != nil {
		panic(fmt.Errorf("MarshalTransactionsBinary failed: %w", err))
	}
	out, err := DecodeTransactions(transactionsData)
	if err != nil {
		panic(fmt.Errorf("DecodeTransactions failed: %w", err))
	}
	for i, txn := range in {
		if txWrapper, ok := txn.(*BlobTxWrapper); ok {
			blobTx := out[i].(*BlobTx)
			out[i] = &BlobTxWrapper{
				// it's ok to copy here - because it's constructor of object - no parallel access yet
				Tx:          *blobTx, //nolint
				Commitments: txWrapper.Commitments.copy(),
				Blobs:       txWrapper.Blobs.copy(),
				Proofs:      txWrapper.Proofs.copy(),
			}
		}
	}
	return out
}

// Copy creates a deep copy of the Block.
func (b *Block) Copy() *Block {
	uncles := make([]*Header, 0, len(b.uncles))
	for _, uncle := range b.uncles {
		uncles = append(uncles, CopyHeader(uncle))
	}

	var withdrawals []*Withdrawal
	if b.withdrawals != nil {
		withdrawals = make([]*Withdrawal, 0, len(b.withdrawals))
		for _, withdrawal := range b.withdrawals {
			wCopy := *withdrawal
			withdrawals = append(withdrawals, &wCopy)
		}
	}

	newB := &Block{
		header:       CopyHeader(b.header),
		uncles:       uncles,
		transactions: CopyTxs(b.transactions),
		withdrawals:  withdrawals,
	}
	szCopy := b.size.Load()
	newB.size.Store(szCopy)
	return newB
}

// WithSeal returns a new block with the data from b but the header replaced with
// the sealed one.
func (b *Block) WithSeal(header *Header) *Block {
	headerCopy := CopyHeader(header)
	headerCopy.mutable = false
	return &Block{
		header:       headerCopy,
		transactions: b.transactions,
		uncles:       b.uncles,
		withdrawals:  b.withdrawals,
	}
}

// Hash returns the keccak256 hash of b's header.
// The hash is computed on the first call and cached thereafter.
func (b *Block) Hash() libcommon.Hash { return b.header.Hash() }

type Blocks []*Block

func DecodeOnlyTxMetadataFromBody(payload []byte) (baseTxnID BaseTxnID, txCount uint32, err error) {
	pos, _, err := rlp2.List(payload, 0)
	if err != nil {
		return baseTxnID, txCount, err
	}
	var btID uint64
	pos, btID, err = rlp2.U64(payload, pos)
	if err != nil {
		return baseTxnID, txCount, err
	}
	baseTxnID = BaseTxnID(btID)

	_, txCount, err = rlp2.U32(payload, pos)
	if err != nil {
		return baseTxnID, txCount, err
	}
	return
}

type BlockWithReceipts struct {
	Block    *Block
	Receipts Receipts
	Requests FlatRequests
}

package types

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"

	libcommon "github.com/erigontech/erigon-lib/common"
	rlp2 "github.com/erigontech/erigon-lib/rlp"
	"github.com/erigontech/erigon/rlp"
)

/* 	===============================
Helper functions
=================================== */

type rlpEncodable interface {
	EncodeRLP(w io.Writer) error
	EncodingSize() int
}

func encodingSizeGeneric[T rlpEncodable](arr []T) (_len int) {
	for _, item := range arr {
		size := item.EncodingSize()
		_len += rlp2.ListPrefixLen(size) + size
	}
	return
}

func encodeRLPGeneric[T rlpEncodable](arr []T, _len int, w io.Writer, b []byte) error {
	if err := EncodeStructSizePrefix(_len, w, b); err != nil {
		return err
	}
	for _, item := range arr {
		if err := item.EncodeRLP(w); err != nil {
			return err
		}
	}
	return nil
}

func decodeTxns(appendList *[]Transaction, s *rlp.Stream) error {
	var err error
	if _, err = s.List(); err != nil {
		return err
	}
	var txn Transaction
	blobTxnsAreWrappedWithBlobs := false
	for txn, err = DecodeRLPTransaction(s, blobTxnsAreWrappedWithBlobs); err == nil; txn, err = DecodeRLPTransaction(s, blobTxnsAreWrappedWithBlobs) {
		*appendList = append(*appendList, txn)
	}
	return checkErrListEnd(s, err)
}

func decodeUncles(appendList *[]*Header, s *rlp.Stream) error {
	var err error
	if _, err = s.List(); err != nil {
		return err
	}
	for err == nil {
		var u Header
		if err = u.DecodeRLP(s); err != nil {
			break
		}
		*appendList = append(*appendList, &u)
	}
	return checkErrListEnd(s, err)
}

func decodeWithdrawals(appendList *[]*Withdrawal, s *rlp.Stream) error {
	var err error
	if _, err = s.List(); err != nil {
		if errors.Is(err, rlp.EOL) {
			*appendList = nil
			return nil // EOL, check for ListEnd is in calling function
		}
		return fmt.Errorf("read Withdrawals: %w", err)
	}
	for err == nil {
		var w Withdrawal
		if err = w.DecodeRLP(s); err != nil {
			break
		}
		*appendList = append(*appendList, &w)
	}
	return checkErrListEnd(s, err)
}

func checkErrListEnd(s *rlp.Stream, err error) error {
	if !errors.Is(err, rlp.EOL) {
		return err
	}
	if err = s.ListEnd(); err != nil {
		return err
	}
	return nil
}

/* 	===============================
Header RLP encoding/decoding
=================================== */

func (h *Header) EncodingSize() int {
	encodingSize := 33 /* ParentHash */ + 33 /* UncleHash */ + 21 /* Coinbase */ + 33 /* Root */ + 33 /* TxHash */ +
		33 /* ReceiptHash */ + 259 /* Bloom */

	encodingSize++
	if h.Difficulty != nil {
		encodingSize += rlp2.BigIntLenExcludingHead(h.Difficulty)
	}
	encodingSize++
	if h.Number != nil {
		encodingSize += rlp2.BigIntLenExcludingHead(h.Number)
	}
	encodingSize++
	encodingSize += rlp2.IntLenExcludingHead(h.GasLimit)
	encodingSize++
	encodingSize += rlp2.IntLenExcludingHead(h.GasUsed)
	encodingSize++
	encodingSize += rlp2.IntLenExcludingHead(h.Time)
	// size of Extra
	encodingSize += rlp2.StringLen(h.Extra)

	if len(h.AuRaSeal) != 0 {
		encodingSize += 1 + rlp2.IntLenExcludingHead(h.AuRaStep)
		encodingSize += rlp2.ListPrefixLen(len(h.AuRaSeal)) + len(h.AuRaSeal)
	} else {
		encodingSize += 33 /* MixDigest */ + 9 /* BlockNonce */
	}

	if h.BaseFee != nil {
		encodingSize++
		encodingSize += rlp2.BigIntLenExcludingHead(h.BaseFee)
	}

	if h.WithdrawalsHash != nil {
		encodingSize += 33
	}

	if h.BlobGasUsed != nil {
		encodingSize++
		encodingSize += rlp2.IntLenExcludingHead(*h.BlobGasUsed)
	}
	if h.ExcessBlobGas != nil {
		encodingSize++
		encodingSize += rlp2.IntLenExcludingHead(*h.ExcessBlobGas)
	}

	if h.ParentBeaconBlockRoot != nil {
		encodingSize += 33
	}

	if h.RequestsHash != nil {
		encodingSize += 33
	}

	if h.Verkle {
		// Encoding of Verkle Proof
		encodingSize += rlp2.StringLen(h.VerkleProof)
		var tmpBuffer bytes.Buffer
		if err := rlp.Encode(&tmpBuffer, h.VerkleKeyVals); err != nil {
			panic(err)
		}
		encodingSize += rlp2.ListPrefixLen(tmpBuffer.Len()) + tmpBuffer.Len()
	}

	return encodingSize
}

func (h *Header) EncodeRLP(w io.Writer) error {
	encodingSize := h.EncodingSize()

	var b [33]byte
	// Prefix
	if err := EncodeStructSizePrefix(encodingSize, w, b[:]); err != nil {
		return err
	}
	b[0] = 128 + 32
	if _, err := w.Write(b[:1]); err != nil {
		return err
	}
	if _, err := w.Write(h.ParentHash.Bytes()); err != nil {
		return err
	}
	if _, err := w.Write(b[:1]); err != nil {
		return err
	}
	if _, err := w.Write(h.UncleHash.Bytes()); err != nil {
		return err
	}
	b[0] = 128 + 20
	if _, err := w.Write(b[:1]); err != nil {
		return err
	}
	if _, err := w.Write(h.Coinbase.Bytes()); err != nil {
		return err
	}
	b[0] = 128 + 32
	if _, err := w.Write(b[:1]); err != nil {
		return err
	}
	if _, err := w.Write(h.Root.Bytes()); err != nil {
		return err
	}
	if _, err := w.Write(b[:1]); err != nil {
		return err
	}
	if _, err := w.Write(h.TxHash.Bytes()); err != nil {
		return err
	}
	if _, err := w.Write(b[:1]); err != nil {
		return err
	}
	if _, err := w.Write(h.ReceiptHash.Bytes()); err != nil {
		return err
	}
	b[0] = 183 + 2
	b[1] = 1
	b[2] = 0
	if _, err := w.Write(b[:3]); err != nil {
		return err
	}
	if _, err := w.Write(h.Bloom.Bytes()); err != nil {
		return err
	}
	if err := rlp2.EncodeBigInt(h.Difficulty, w, b[:]); err != nil {
		return err
	}
	if err := rlp2.EncodeBigInt(h.Number, w, b[:]); err != nil {
		return err
	}
	if err := rlp2.EncodeInt(h.GasLimit, w, b[:]); err != nil {
		return err
	}
	if err := rlp2.EncodeInt(h.GasUsed, w, b[:]); err != nil {
		return err
	}
	if err := rlp2.EncodeInt(h.Time, w, b[:]); err != nil {
		return err
	}
	if err := rlp2.EncodeStringToWriter(h.Extra, w, b[:]); err != nil {
		return err
	}

	if len(h.AuRaSeal) > 0 {
		if err := rlp2.EncodeInt(h.AuRaStep, w, b[:]); err != nil {
			return err
		}
		if err := rlp2.EncodeStringToWriter(h.AuRaSeal, w, b[:]); err != nil {
			return err
		}
	} else {
		b[0] = 128 + 32
		if _, err := w.Write(b[:1]); err != nil {
			return err
		}
		if _, err := w.Write(h.MixDigest.Bytes()); err != nil {
			return err
		}
		b[0] = 128 + 8
		if _, err := w.Write(b[:1]); err != nil {
			return err
		}
		if _, err := w.Write(h.Nonce[:]); err != nil {
			return err
		}
	}

	if h.BaseFee != nil {
		if err := rlp2.EncodeBigInt(h.BaseFee, w, b[:]); err != nil {
			return err
		}
	}

	if h.WithdrawalsHash != nil {
		b[0] = 128 + 32
		if _, err := w.Write(b[:1]); err != nil {
			return err
		}
		if _, err := w.Write(h.WithdrawalsHash.Bytes()); err != nil {
			return err
		}
	}

	if h.BlobGasUsed != nil {
		if err := rlp2.EncodeInt(*h.BlobGasUsed, w, b[:]); err != nil {
			return err
		}
	}
	if h.ExcessBlobGas != nil {
		if err := rlp2.EncodeInt(*h.ExcessBlobGas, w, b[:]); err != nil {
			return err
		}
	}

	if h.ParentBeaconBlockRoot != nil {
		b[0] = 128 + 32
		if _, err := w.Write(b[:1]); err != nil {
			return err
		}
		if _, err := w.Write(h.ParentBeaconBlockRoot.Bytes()); err != nil {
			return err
		}
	}

	if h.RequestsHash != nil {
		b[0] = 128 + 32
		if _, err := w.Write(b[:1]); err != nil {
			return err
		}
		if _, err := w.Write(h.RequestsHash.Bytes()); err != nil {
			return err
		}
	}

	if h.Verkle {
		if err := rlp2.EncodeStringToWriter(h.VerkleProof, w, b[:]); err != nil {
			return err
		}

		if err := rlp.Encode(w, h.VerkleKeyVals); err != nil {
			return nil
		}
	}

	return nil
}

func (h *Header) DecodeRLP(s *rlp.Stream) error {
	_, err := s.List()
	if err != nil {
		return err
		// return fmt.Errorf("open header struct: %w", err)
	}
	var b []byte
	if b, err = s.Bytes(); err != nil {
		return fmt.Errorf("read ParentHash: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("wrong size for ParentHash: %d", len(b))
	}
	copy(h.ParentHash[:], b)
	if b, err = s.Bytes(); err != nil {
		return fmt.Errorf("read UncleHash: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("wrong size for UncleHash: %d", len(b))
	}
	copy(h.UncleHash[:], b)
	if b, err = s.Bytes(); err != nil {
		return fmt.Errorf("read Coinbase: %w", err)
	}
	if len(b) != 20 {
		return fmt.Errorf("wrong size for Coinbase: %d", len(b))
	}
	copy(h.Coinbase[:], b)
	if b, err = s.Bytes(); err != nil {
		return fmt.Errorf("read Root: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("wrong size for Root: %d", len(b))
	}
	copy(h.Root[:], b)
	if b, err = s.Bytes(); err != nil {
		return fmt.Errorf("read TxHash: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("wrong size for TxHash: %d", len(b))
	}
	copy(h.TxHash[:], b)
	if b, err = s.Bytes(); err != nil {
		return fmt.Errorf("read ReceiptHash: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("wrong size for ReceiptHash: %d", len(b))
	}
	copy(h.ReceiptHash[:], b)
	if b, err = s.Bytes(); err != nil {
		return fmt.Errorf("read Bloom: %w", err)
	}
	if len(b) != 256 {
		return fmt.Errorf("wrong size for Bloom: %d", len(b))
	}
	copy(h.Bloom[:], b)
	if b, err = s.Uint256Bytes(); err != nil {
		return fmt.Errorf("read Difficulty: %w", err)
	}
	h.Difficulty = new(big.Int).SetBytes(b)
	if b, err = s.Uint256Bytes(); err != nil {
		return fmt.Errorf("read Number: %w", err)
	}
	h.Number = new(big.Int).SetBytes(b)
	if h.GasLimit, err = s.Uint(); err != nil {
		return fmt.Errorf("read GasLimit: %w", err)
	}
	if h.GasUsed, err = s.Uint(); err != nil {
		return fmt.Errorf("read GasUsed: %w", err)
	}
	if h.Time, err = s.Uint(); err != nil {
		return fmt.Errorf("read Time: %w", err)
	}
	if h.Extra, err = s.Bytes(); err != nil {
		return fmt.Errorf("read Extra: %w", err)
	}

	_, size, err := s.Kind()
	if err != nil {
		return fmt.Errorf("read MixDigest: %w", err)
	}
	if size != 32 { // AuRa
		if h.AuRaStep, err = s.Uint(); err != nil {
			return fmt.Errorf("read AuRaStep: %w", err)
		}
		if h.AuRaSeal, err = s.Bytes(); err != nil {
			return fmt.Errorf("read AuRaSeal: %w", err)
		}
	} else {
		if b, err = s.Bytes(); err != nil {
			return fmt.Errorf("read MixDigest: %w", err)
		}
		copy(h.MixDigest[:], b)
		if b, err = s.Bytes(); err != nil {
			return fmt.Errorf("read Nonce: %w", err)
		}
		if len(b) != 8 {
			return fmt.Errorf("wrong size for Nonce: %d", len(b))
		}
		copy(h.Nonce[:], b)
	}

	// BaseFee
	if b, err = s.Uint256Bytes(); err != nil {
		if errors.Is(err, rlp.EOL) {
			h.BaseFee = nil
			if err := s.ListEnd(); err != nil {
				return fmt.Errorf("close header struct (no BaseFee): %w", err)
			}
			return nil
		}
		return fmt.Errorf("read BaseFee: %w", err)
	}
	h.BaseFee = new(big.Int).SetBytes(b)

	// WithdrawalsHash
	if b, err = s.Bytes(); err != nil {
		if errors.Is(err, rlp.EOL) {
			h.WithdrawalsHash = nil
			if err := s.ListEnd(); err != nil {
				return fmt.Errorf("close header struct (no WithdrawalsHash): %w", err)
			}
			return nil
		}
		return fmt.Errorf("read WithdrawalsHash: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("wrong size for WithdrawalsHash: %d", len(b))
	}
	h.WithdrawalsHash = new(libcommon.Hash)
	h.WithdrawalsHash.SetBytes(b)

	var blobGasUsed uint64
	if blobGasUsed, err = s.Uint(); err != nil {
		if errors.Is(err, rlp.EOL) {
			h.BlobGasUsed = nil
			if err := s.ListEnd(); err != nil {
				return fmt.Errorf("close header struct (no BlobGasUsed): %w", err)
			}
			return nil
		}
		return fmt.Errorf("read BlobGasUsed: %w", err)
	}
	h.BlobGasUsed = &blobGasUsed

	var excessBlobGas uint64
	if excessBlobGas, err = s.Uint(); err != nil {
		if errors.Is(err, rlp.EOL) {
			h.ExcessBlobGas = nil
			if err := s.ListEnd(); err != nil {
				return fmt.Errorf("close header struct (no ExcessBlobGas): %w", err)
			}
			return nil
		}
		return fmt.Errorf("read ExcessBlobGas: %w", err)
	}
	h.ExcessBlobGas = &excessBlobGas

	// ParentBeaconBlockRoot
	if b, err = s.Bytes(); err != nil {
		if errors.Is(err, rlp.EOL) {
			h.ParentBeaconBlockRoot = nil
			if err := s.ListEnd(); err != nil {
				return fmt.Errorf("close header struct (no ParentBeaconBlockRoot): %w", err)
			}
			return nil
		}
		return fmt.Errorf("read ParentBeaconBlockRoot: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("wrong size for ParentBeaconBlockRoot: %d", len(b))
	}
	h.ParentBeaconBlockRoot = new(libcommon.Hash)
	h.ParentBeaconBlockRoot.SetBytes(b)

	// RequestsHash
	if b, err = s.Bytes(); err != nil {
		if errors.Is(err, rlp.EOL) {
			h.RequestsHash = nil
			if err := s.ListEnd(); err != nil {
				return fmt.Errorf("close header struct (no RequestsHash): %w", err)
			}
			return nil
		}
		return fmt.Errorf("read RequestsHash: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("wrong size for RequestsHash: %d", len(b))
	}
	h.RequestsHash = new(libcommon.Hash)
	h.RequestsHash.SetBytes(b)

	if h.Verkle {
		if h.VerkleProof, err = s.Bytes(); err != nil {
			return fmt.Errorf("read VerkleProof: %w", err)
		}
		rawKv, err := s.Raw()
		if err != nil {
			return err
		}
		rlp.DecodeBytes(rawKv, h.VerkleKeyVals)
	}

	if err := s.ListEnd(); err != nil {
		return fmt.Errorf("close header struct: %w", err)
	}
	return nil
}

/* 	===============================
RawBody RLP encoding/decoding
=================================== */

func (rb RawBody) EncodingSize() int {
	payloadSize, _, _, _ := rb.payloadSize()
	return payloadSize
}

func (rb RawBody) payloadSize() (payloadSize, txsLen, unclesLen, withdrawalsLen int) {
	// size of Transactions
	for _, txn := range rb.Transactions {
		txsLen += len(txn)
	}
	payloadSize += rlp2.ListPrefixLen(txsLen) + txsLen

	// size of Uncles
	unclesLen += encodingSizeGeneric(rb.Uncles)
	payloadSize += rlp2.ListPrefixLen(unclesLen) + unclesLen

	// size of Withdrawals
	if rb.Withdrawals != nil {
		withdrawalsLen += encodingSizeGeneric(rb.Withdrawals)
		payloadSize += rlp2.ListPrefixLen(withdrawalsLen) + withdrawalsLen
	}

	return payloadSize, txsLen, unclesLen, withdrawalsLen
}

func (rb RawBody) EncodeRLP(w io.Writer) error {
	payloadSize, txsLen, unclesLen, withdrawalsLen := rb.payloadSize()
	var b [33]byte
	// prefix
	if err := EncodeStructSizePrefix(payloadSize, w, b[:]); err != nil {
		return err
	}
	// encode Transactions
	if err := EncodeStructSizePrefix(txsLen, w, b[:]); err != nil {
		return err
	}
	for _, txn := range rb.Transactions {
		if _, err := w.Write(txn); err != nil {
			return nil
		}
	}
	// encode Uncles
	if err := encodeRLPGeneric(rb.Uncles, unclesLen, w, b[:]); err != nil {
		return err
	}
	// encode Withdrawals
	if rb.Withdrawals != nil {
		if err := encodeRLPGeneric(rb.Withdrawals, withdrawalsLen, w, b[:]); err != nil {
			return err
		}
	}
	return nil
}

func (rb *RawBody) DecodeRLP(s *rlp.Stream) error {
	_, err := s.List()
	if err != nil {
		fmt.Println("THIS ERR")
		return err
	}
	// decode Transactions
	if _, err = s.List(); err != nil {
		fmt.Println("THIS ERR")
		return err
	}
	var txn []byte
	for txn, err = s.Raw(); err == nil; txn, err = s.Raw() {
		if txn == nil {
			return errors.New("RawBody.DecodeRLP txn nil")
		}
		rb.Transactions = append(rb.Transactions, txn)
	}
	if !errors.Is(err, rlp.EOL) {
		return err
	}
	// end of Transactions
	if err = s.ListEnd(); err != nil {
		return err
	}
	// decode Uncles
	if err := decodeUncles(&rb.Uncles, s); err != nil {
		return err
	}
	// decode Withdrawals
	rb.Withdrawals = []*Withdrawal{}
	if err := decodeWithdrawals(&rb.Withdrawals, s); err != nil {
		return err
	}

	return s.ListEnd()
}

/* 	===============================
BodyForStorage RLP encoding/decoding
=================================== */

func (bfs BodyForStorage) payloadSize() (payloadSize, unclesLen, withdrawalsLen int) {
	baseTxnIDLen := 1 + rlp2.IntLenExcludingHead(bfs.BaseTxnID.U64())
	txCountLen := 1 + rlp2.IntLenExcludingHead(uint64(bfs.TxCount))

	payloadSize += baseTxnIDLen
	payloadSize += txCountLen

	// size of Uncles
	unclesLen += encodingSizeGeneric(bfs.Uncles)
	payloadSize += rlp2.ListPrefixLen(unclesLen) + unclesLen

	// size of Withdrawals
	if bfs.Withdrawals != nil {
		withdrawalsLen += encodingSizeGeneric(bfs.Withdrawals)
		payloadSize += rlp2.ListPrefixLen(withdrawalsLen) + withdrawalsLen
	}

	return payloadSize, unclesLen, withdrawalsLen
}

func (bfs BodyForStorage) EncodeRLP(w io.Writer) error {
	payloadSize, unclesLen, withdrawalsLen := bfs.payloadSize()
	var b [33]byte

	// prefix
	if err := EncodeStructSizePrefix(payloadSize, w, b[:]); err != nil {
		return err
	}

	// encode BaseTxId
	if err := rlp.Encode(w, bfs.BaseTxnID); err != nil {
		return err
	}

	// encode TxCount
	if err := rlp.Encode(w, bfs.TxCount); err != nil {
		return err
	}

	// encode Uncles
	if err := encodeRLPGeneric(bfs.Uncles, unclesLen, w, b[:]); err != nil {
		return err
	}
	// encode Withdrawals
	// nil if pre-shanghai, empty slice if shanghai and no withdrawals in block, otherwise non-empty
	if bfs.Withdrawals != nil {
		if err := encodeRLPGeneric(bfs.Withdrawals, withdrawalsLen, w, b[:]); err != nil {
			return err
		}
	}

	return nil
}

func (bfs *BodyForStorage) DecodeRLP(s *rlp.Stream) error {
	_, err := s.List()
	if err != nil {
		return err
	}

	// decode BaseTxId
	if err = s.Decode(&bfs.BaseTxnID); err != nil {
		return err
	}
	// decode TxCount
	if err = s.Decode(&bfs.TxCount); err != nil {
		return err
	}
	// decode Uncles
	if err := decodeUncles(&bfs.Uncles, s); err != nil {
		return err
	}
	// decode Withdrawals
	bfs.Withdrawals = []*Withdrawal{}
	if err := decodeWithdrawals(&bfs.Withdrawals, s); err != nil {
		return err
	}
	return s.ListEnd()
}

/* 	===============================
Body RLP encoding/decoding
=================================== */

func (bb Body) EncodingSize() int {
	payloadSize, _, _, _ := bb.payloadSize()
	return payloadSize
}

func (bb Body) payloadSize() (payloadSize int, txsLen, unclesLen, withdrawalsLen int) {
	// size of Transactions
	txsLen += encodingSizeGeneric(bb.Transactions)
	payloadSize += rlp2.ListPrefixLen(txsLen) + txsLen

	// size of Uncles
	unclesLen += encodingSizeGeneric(bb.Uncles)
	payloadSize += rlp2.ListPrefixLen(unclesLen) + unclesLen

	// size of Withdrawals
	if bb.Withdrawals != nil {
		withdrawalsLen += encodingSizeGeneric(bb.Withdrawals)
		payloadSize += rlp2.ListPrefixLen(withdrawalsLen) + withdrawalsLen
	}

	return payloadSize, txsLen, unclesLen, withdrawalsLen
}

func (bb Body) EncodeRLP(w io.Writer) error {
	payloadSize, txsLen, unclesLen, withdrawalsLen := bb.payloadSize()
	var b [33]byte
	// prefix
	if err := EncodeStructSizePrefix(payloadSize, w, b[:]); err != nil {
		return err
	}
	// encode Transactions
	if err := encodeRLPGeneric(bb.Transactions, txsLen, w, b[:]); err != nil {
		return err
	}
	// encode Uncles
	if err := encodeRLPGeneric(bb.Uncles, unclesLen, w, b[:]); err != nil {
		return err
	}
	// encode Withdrawals
	if bb.Withdrawals != nil {
		if err := encodeRLPGeneric(bb.Withdrawals, withdrawalsLen, w, b[:]); err != nil {
			return err
		}
	}
	return nil
}

func (bb *Body) DecodeRLP(s *rlp.Stream) error {
	_, err := s.List()
	if err != nil {
		return err
	}
	// decode Transactions
	if err := decodeTxns(&bb.Transactions, s); err != nil {
		return err
	}
	// decode Uncles
	if err := decodeUncles(&bb.Uncles, s); err != nil {
		return err
	}
	// decode Withdrawals
	bb.Withdrawals = []*Withdrawal{}
	if err := decodeWithdrawals(&bb.Withdrawals, s); err != nil {
		return err
	}

	return s.ListEnd()
}

/* 	===============================
Body RLP encoding/decoding
=================================== */

func (bb *Block) payloadSize() (payloadSize int, txsLen, unclesLen, withdrawalsLen int) {
	// size of Header
	headerLen := bb.header.EncodingSize()
	payloadSize += rlp2.ListPrefixLen(headerLen) + headerLen

	// size of Transactions
	txsLen += encodingSizeGeneric(bb.transactions)
	payloadSize += rlp2.ListPrefixLen(txsLen) + txsLen

	// size of Uncles
	unclesLen += encodingSizeGeneric(bb.uncles)
	payloadSize += rlp2.ListPrefixLen(unclesLen) + unclesLen

	// size of Withdrawals
	if bb.withdrawals != nil {
		withdrawalsLen += encodingSizeGeneric(bb.withdrawals)
		payloadSize += rlp2.ListPrefixLen(withdrawalsLen) + withdrawalsLen
	}

	return payloadSize, txsLen, unclesLen, withdrawalsLen
}

func (bb *Block) EncodingSize() int {
	payloadSize, _, _, _ := bb.payloadSize()
	return payloadSize
}

// EncodeRLP serializes b into the Ethereum RLP block format.
func (bb *Block) EncodeRLP(w io.Writer) error {
	payloadSize, txsLen, unclesLen, withdrawalsLen := bb.payloadSize()
	var b [33]byte
	// prefix
	if err := EncodeStructSizePrefix(payloadSize, w, b[:]); err != nil {
		return err
	}
	// encode Header
	if err := bb.header.EncodeRLP(w); err != nil {
		return err
	}
	// encode Transactions
	if err := encodeRLPGeneric(bb.transactions, txsLen, w, b[:]); err != nil {
		return err
	}
	// encode Uncles
	if err := encodeRLPGeneric(bb.uncles, unclesLen, w, b[:]); err != nil {
		return err
	}
	// encode Withdrawals
	if bb.withdrawals != nil {
		if err := encodeRLPGeneric(bb.withdrawals, withdrawalsLen, w, b[:]); err != nil {
			return err
		}
	}

	return nil
}

func (bb *Block) DecodeRLP(s *rlp.Stream) error {
	size, err := s.List()
	if err != nil {
		return err
	}
	bb.size.Store(rlp.ListSize(size))

	// decode header
	var h Header
	if err = h.DecodeRLP(s); err != nil {
		return err
	}
	bb.header = &h

	// decode Transactions
	if err := decodeTxns((*[]Transaction)(&bb.transactions), s); err != nil {
		return err
	}
	// decode Uncles
	if err := decodeUncles(&bb.uncles, s); err != nil {
		return err
	}
	// decode Withdrawals
	bb.withdrawals = []*Withdrawal{}
	if err := decodeWithdrawals(&bb.withdrawals, s); err != nil {
		return err
	}

	return s.ListEnd()
}

/* 	===============================
Log RLP encoding/decoding
=================================== */

func (l *Log) payloadSize() (payloadSize, topicsLen int) {
	payloadSize += 21              // Address  + prefix
	topicsLen = len(l.Topics) * 33 // each hash = 32 byte long + 1 prefix
	payloadSize += rlp2.ListPrefixLen(topicsLen) + topicsLen
	payloadSize += rlp2.StringLen(l.Data)
	return
}

// func (l *Log) EncodingSize() int {

// }

// EncodeRLP serializes b into the Ethereum RLP block format.
func (l *Log) encodeRLP(w io.Writer) error {
	payloadSize, topicsLen := l.payloadSize()
	var b [33]byte
	// prefix
	if err := EncodeStructSizePrefix(payloadSize, w, b[:]); err != nil {
		return err
	}
	// encode address
	b[0] = 128 + 20
	if _, err := w.Write(b[:1]); err != nil {
		return err
	}
	if _, err := w.Write(l.Address[:]); err != nil {
		return err
	}
	// encode topics
	if err := EncodeStructSizePrefix(topicsLen, w, b[:]); err != nil {
		return err
	}
	b[0] = 128 + 32
	for _, h := range l.Topics {
		if _, err := w.Write(b[:1]); err != nil {
			return err
		}
		if _, err := w.Write(h[:]); err != nil {
			return err
		}
	}

	// encode data
	if err := rlp2.EncodeStringToWriter(l.Data, w, b[:]); err != nil {
		return err
	}

	return nil
}

func (l *Log) decodeRLP(s *rlp.Stream) error {
	_, err := s.List()
	if err != nil {
		return err
	}
	var b []byte

	// decode Address
	if b, err = s.Bytes(); err != nil {
		return err
	}
	if len(b) > 0 && len(b) != 20 {
		return fmt.Errorf("wrong size for To: %d", len(b))
	}
	l.Address = libcommon.Address{}
	copy((l.Address)[:], b)

	// decode Topics
	_, err = s.List()
	if err != nil {
		return fmt.Errorf("open Topics: %w", err)
	}
	l.Topics = []libcommon.Hash{}
	_hash := libcommon.Hash{}
	for b, err = s.Bytes(); err == nil; b, err = s.Bytes() {
		if len(b) == 32 {
			copy((_hash)[:], b)
			l.Topics = append(l.Topics, _hash)
		} else {
			return fmt.Errorf("wrong size for Topic: %d, expected 32", len(b))
		}
	}
	if err = s.ListEnd(); err != nil {
		return fmt.Errorf("close Topics: %w", err)
	}

	// decode Data
	if l.Data, err = s.Bytes(); err != nil {
		return err
	}

	return s.ListEnd()
}

/* 	===============================
ReceiptForStorage RLP encoding/decoding
=================================== */

func (r *ReceiptForStorage) payloadSize() (payloadSize int) {
	payloadSize += rlp2.StringLen((*Receipt)(r).statusEncoding())
	payloadSize++
	payloadSize += rlp2.IntLenExcludingHead(r.CumulativeGasUsed)
	payloadSize++
	if len(r.Logs) > 0 {
		payloadSize += rlp2.IntLenExcludingHead(uint64(r.Logs[0].Index))
	} else {
		payloadSize += rlp2.IntLenExcludingHead(0)
	}
	return
}

func (r *ReceiptForStorage) encodeRLP(w io.Writer) error {

	payloadSize := r.payloadSize()
	var b [32]byte
	// prefix
	if err := EncodeStructSizePrefix(payloadSize, w, b[:]); err != nil {
		return err
	}

	if err := rlp2.EncodeStringToWriter((*Receipt)(r).statusEncoding(), w, b[:]); err != nil {
		return err
	}

	if err := rlp2.EncodeInt(r.CumulativeGasUsed, w, b[:]); err != nil {
		return err
	}

	if len(r.Logs) > 0 {
		if err := rlp2.EncodeInt(uint64(r.Logs[0].Index), w, b[:]); err != nil {
			return err
		}
	} else {
		if err := rlp2.EncodeInt(0, w, b[:]); err != nil {
			return err
		}
	}
	return nil
}

func (r *ReceiptForStorage) decodeRLP(s *rlp.Stream) error {
	_, err := s.List()
	if err != nil {
		return err
	}
	var b []byte
	if b, err = s.Bytes(); err != nil {
		return err
	}
	if err := (*Receipt)(r).setStatus(b); err != nil {
		return err
	}
	if r.CumulativeGasUsed, err = s.Uint(); err != nil {
		return err
	}
	var n uint64
	if n, err = s.Uint(); err != nil {
		return err
	}
	r.FirstLogIndexWithinBlock = uint32(n)

	return nil
}

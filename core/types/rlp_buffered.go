package types

import (
	"bytes"
	"io"
	"math/big"
	"math/bits"
	"sync"

	"github.com/erigontech/erigon-lib/common"
	libcommon "github.com/erigontech/erigon-lib/common"
	rlp2 "github.com/erigontech/erigon-lib/rlp"
	"github.com/erigontech/erigon/rlp"
)

var (
	emptyStringCode byte = 0x80
	emptyListCode   byte = 0xC0

	hashLenghWithPrefix = 33
	addrLenghWithPrefix = 21

	bitsShift = []int{0, 0, 8, 16, 24, 32, 40, 48, 56} // if number can be respresented with 1 byte then shift nothing, if with 2 bytes shift 8 bits, if 3 bytes -> 16, 4 -> 24, and so on
)

type encBuffer struct {
	str  []byte
	size int
}

var encBufferPool = sync.Pool{
	New: func() interface{} { return new(encBuffer) },
}

func (buf *encBuffer) reset() {
	buf.str = buf.str[:0]
	buf.size = 0
}

func (buf *encBuffer) flush(w io.Writer) error {
	if _, err := w.Write(buf.str); err != nil {
		return err
	}
	return nil
}

func (buf *encBuffer) append(b byte) {
	buf.str = append(buf.str, b)
	buf.size++
}

func (buf *encBuffer) appendList(b []byte) {
	buf.str = append(buf.str, b...)
	buf.size += len(b)
}

func (buf *encBuffer) encodeHeader(list bool, payloadSize int) {
	var prefix byte
	if payloadSize < 56 {
		if list {
			prefix = emptyListCode
		} else {
			prefix = emptyStringCode
		}
		// buf.append(prefix + byte(payloadSize))
		buf.str = append(buf.str, prefix+byte(payloadSize))
		buf.size++
	} else {
		size := libcommon.BitLenToByteLen(bits.Len64(uint64(payloadSize)))
		if list {
			prefix = 0xF7
		} else {
			prefix = 0xB7
		}
		// buf.append(prefix + byte(size))
		buf.str = append(buf.str, prefix+byte(size))
		// buf.size++
		// n := bitsShift[size]
		// for n >= 0 {
		// 	// buf.append(byte(payloadSize >> n))
		// 	buf.str = append(buf.str, byte(payloadSize>>n))
		// 	// buf.size++
		// 	n -= 8
		// }

		a := make([]byte, 8)
		a[0] = byte(payloadSize >> 56)
		a[1] = byte(payloadSize >> 48)
		a[2] = byte(payloadSize >> 40)
		a[3] = byte(payloadSize >> 32)
		a[4] = byte(payloadSize >> 24)
		a[5] = byte(payloadSize >> 16)
		a[6] = byte(payloadSize >> 8)
		a[7] = byte(payloadSize)
		buf.str = append(buf.str, a[8-size:]...)

		buf.size += size + 1
	}
}

func (buf *encBuffer) encodeBigInt(i *big.Int) {
	bitLen := i.BitLen() // treat nil as 0
	if bitLen < 8 {
		if bitLen > 0 {
			// buf.append(byte(i.Uint64()))
			buf.str = append(buf.str, byte(i.Uint64()))
			buf.size++
		} else {
			// buf.append(0x80)
			buf.str = append(buf.str, 0x80)
			buf.size++
		}
	}

	size := common.BitLenToByteLen(bitLen)
	// buf.append(0x80 + byte(size))
	buf.str = append(buf.str, 0x80+byte(size))
	buf.str = append(buf.str, make([]byte, size)...)
	buf.size += size + 1
	i.FillBytes(buf.str[buf.size-size : buf.size])
}

func (buf *encBuffer) encodeInt(i uint64) {
	if 0 < i && i < 0x80 {
		// buf.append(byte(i))
		buf.str = append(buf.str, byte(i))
		buf.size++
		return
	}

	size := common.BitLenToByteLen(bits.Len64(i))
	// buf.append(0x80 + byte(size))
	buf.str = append(buf.str, 0x80+byte(size))

	a := make([]byte, 8)
	a[0] = byte(i >> 56)
	a[1] = byte(i >> 48)
	a[2] = byte(i >> 40)
	a[3] = byte(i >> 32)
	a[4] = byte(i >> 24)
	a[5] = byte(i >> 16)
	a[6] = byte(i >> 8)
	a[7] = byte(i)

	buf.str = append(buf.str, a[8-size:]...)
	buf.size += size + 1
}

func (buf *encBuffer) encodeBytes(src []byte) {
	buf.encodeHeader(false, len(src))
	buf.appendList(src)
}

func (buf *encBuffer) encodeHash(src libcommon.Hash) {
	buf.encodeHeader(true, 33)
	buf.appendList(src[:])
}

func (buf *encBuffer) encodeSliceOfHashes(src []libcommon.Hash) (idx int) {
	buf.encodeHeader(true, 33*len(src))
	for i := 0; i < len(src); i++ {
		buf.encodeBytes(src[i][:])
	}
	return
}

/* 	===============================
Header RLP encoding/decoding
=================================== */

func (h *Header) rlpHeader() (list bool, payloadSize int) {
	list = true
	payloadSize += hashLenghWithPrefix // parentHash
	payloadSize += hashLenghWithPrefix // uncleHash
	payloadSize += addrLenghWithPrefix // coinbase
	payloadSize += hashLenghWithPrefix // root
	payloadSize += hashLenghWithPrefix // txHash
	payloadSize += hashLenghWithPrefix // receiptHash
	payloadSize += 259                 // bloom

	payloadSize++
	if h.Difficulty != nil {
		payloadSize += rlp2.BigIntLenExcludingHead(h.Difficulty)
	}
	payloadSize++
	if h.Number != nil {
		payloadSize += rlp2.BigIntLenExcludingHead(h.Number)
	}
	payloadSize++
	payloadSize += rlp2.IntLenExcludingHead(h.GasLimit)
	payloadSize++
	payloadSize += rlp2.IntLenExcludingHead(h.GasUsed)
	payloadSize++
	payloadSize += rlp2.IntLenExcludingHead(h.Time)
	// size of Extra
	payloadSize += rlp2.StringLen(h.Extra)

	if len(h.AuRaSeal) != 0 {
		payloadSize += 1 + rlp2.IntLenExcludingHead(h.AuRaStep)
		payloadSize += rlp2.ListPrefixLen(len(h.AuRaSeal)) + len(h.AuRaSeal)
	} else {
		payloadSize += 33 /* MixDigest */ + 9 /* BlockNonce */
	}

	if h.BaseFee != nil {
		payloadSize++
		payloadSize += rlp2.BigIntLenExcludingHead(h.BaseFee)
	}

	if h.WithdrawalsHash != nil {
		payloadSize += 33
	}

	if h.BlobGasUsed != nil {
		payloadSize++
		payloadSize += rlp2.IntLenExcludingHead(*h.BlobGasUsed)
	}
	if h.ExcessBlobGas != nil {
		payloadSize++
		payloadSize += rlp2.IntLenExcludingHead(*h.ExcessBlobGas)
	}

	if h.ParentBeaconBlockRoot != nil {
		payloadSize += 33
	}

	if h.RequestsHash != nil {
		payloadSize += 33
	}

	if h.Verkle {
		// Encoding of Verkle Proof
		payloadSize += rlp2.StringLen(h.VerkleProof)
		var tmpBuffer bytes.Buffer
		if err := rlp.Encode(&tmpBuffer, h.VerkleKeyVals); err != nil {
			panic(err)
		}
		payloadSize += rlp2.ListPrefixLen(tmpBuffer.Len()) + tmpBuffer.Len()
	}

	return
}

func (h *Header) encodeRLP(w io.Writer) error {
	buf := encBufferPool.Get().(*encBuffer)
	defer encBufferPool.Put(buf)
	buf.reset()

	list, payloadSize := h.rlpHeader()
	buf.encodeHeader(list, payloadSize)
	buf.encodeBytes(h.ParentHash[:])
	buf.encodeBytes(h.UncleHash[:])
	buf.encodeBytes(h.Coinbase[:])
	buf.encodeBytes(h.Root[:])
	buf.encodeBytes(h.TxHash[:])
	buf.encodeBytes(h.ReceiptHash[:])
	buf.encodeBytes(h.Bloom[:])

	buf.encodeBigInt(h.Difficulty)
	buf.encodeBigInt(h.Number)
	buf.encodeInt(h.GasLimit)
	buf.encodeInt(h.GasUsed)
	buf.encodeInt(h.Time)
	buf.encodeBytes(h.Extra)

	if len(h.AuRaSeal) > 0 {
		buf.encodeInt(h.AuRaStep)
		buf.encodeBytes(h.AuRaSeal)
	} else {
		buf.encodeBytes(h.MixDigest[:])
		buf.encodeBytes(h.Nonce[:])
	}
	if h.BaseFee != nil {
		buf.encodeBigInt(h.BaseFee)
	}
	if h.WithdrawalsHash != nil {
		buf.encodeBytes(h.WithdrawalsHash[:])
	}
	if h.BlobGasUsed != nil {
		buf.encodeInt(*h.BlobGasUsed)
	}
	if h.ExcessBlobGas != nil {
		buf.encodeInt(*h.ExcessBlobGas)
	}
	if h.ParentBeaconBlockRoot != nil {
		buf.encodeBytes(h.ParentBeaconBlockRoot[:])
	}
	if h.RequestsHash != nil {
		buf.encodeBytes(h.RequestsHash[:])
	}
	if h.Verkle {
		buf.encodeBytes(h.VerkleProof)
		// TODO(racytech)
	}

	return buf.flush(w)
}

/* 	===============================
Log RLP encoding/decoding
=================================== */

func (l *Log) rlpHeader() (list bool, payloadSize int) {
	list = true
	payloadSize += 21               // Address  + prefix
	topicsLen := len(l.Topics) * 33 // each hash = 32 byte long + 1 prefix
	payloadSize += rlp2.ListPrefixLen(topicsLen) + topicsLen
	payloadSize += rlp2.StringLen(l.Data)
	return true, payloadSize
}

func (l *Log) _encodeRLP(w io.Writer) error {
	buf := encBufferPool.Get().(*encBuffer)
	defer encBufferPool.Put(buf)
	buf.reset()

	list, payloadSize := l.rlpHeader()
	buf.encodeHeader(list, payloadSize)
	buf.encodeBytes(l.Address[:])
	buf.encodeSliceOfHashes(l.Topics)
	buf.encodeBytes(l.Data)

	return buf.flush(w)
}

package headers

import (
	"math"

	"github.com/mangekyou-network/eccBSC/gadgets/conv"
	"github.com/mangekyou-network/eccBSC/gadgets/keccak"
	"github.com/mangekyou-network/eccBSC/gadgets/merkle"
	"github.com/mangekyou-network/eccBSC/gadgets/rlp"

	"github.com/consensys/gnark/frontend"
)

type BNBCircuit struct {
	ChunkRoot     [2]frontend.Variable `gnark:",public"`
	PrevHash      [2]frontend.Variable `gnark:",public"`
	EndHash       [2]frontend.Variable `gnark:",public"`
	StartBlockNum frontend.Variable    `gnark:",public"`
	EndBlockNum   frontend.Variable    `gnark:",public"`

	// RLP encoded header bits, pre-padded with 10..1 for keccak, additional zeros are padded in the end
	// to fill up to maxRounds * 1088
	Headers       [][]frontend.Variable
	HashRoundIdxs []frontend.Variable

	api frontend.API
}

func (c *BNBCircuit) Define(api frontend.API) error {
	c.api = api
	if !isPowerOfTwo(len(c.Headers)) {
		panic("headers len must be power of two")
	}
	blockHashes := c.computeBlockHashes()
	parentHashes := c.decodeParentHashes()
	c.checkConnectivity(blockHashes, parentHashes)
	c.checkBoundary(parentHashes[0])
	c.checkMerkleRoot(blockHashes)
	return nil
}

func (c *BNBCircuit) computeBlockHashes() [][256]frontend.Variable {
	blockHashes := [][256]frontend.Variable{}
	for i := 0; i < len(c.Headers); i++ {
		header := c.Headers[i]
		roundIdx := c.HashRoundIdxs[i]
		hash := keccak.Keccak256Bits(c.api, CHUNK_HEADER_MAX_HASH_ROUNDS, roundIdx, header)
		blockHashes = append(blockHashes, hash)
	}
	return blockHashes
}

func (c *BNBCircuit) checkMerkleRoot(blockHashes [][256]frontend.Variable) {
	root := merkle.KeccakMerkleRoot(c.api, blockHashes)
	rootHash := conv.Bits2Uint128s(c.api, root)
	for i := 0; i < 2; i++ {
		c.api.AssertIsEqual(c.ChunkRoot[i], rootHash[i])
	}
}

func (c *BNBCircuit) checkBoundary(prevHash [256]frontend.Variable) {
	prev := conv.Bits2Uint128s(c.api, prevHash)
	for i := 0; i < 2; i++ {
		c.api.AssertIsEqual(prev[i], c.PrevHash[i])
	}
	startBlockNum := c.decodeBlockNumber(c.Headers[0])
	endBlockNum := c.decodeBlockNumber(c.Headers[len(c.Headers)-1])
	c.api.AssertIsEqual(startBlockNum, c.StartBlockNum)
	c.api.AssertIsEqual(endBlockNum, c.EndBlockNum)
}

func (c *BNBCircuit) checkConnectivity(blockHashes [][256]frontend.Variable, parentHashes [][256]frontend.Variable) {
	for i := 1; i < len(blockHashes); i++ {
		// TODO perf opt: merge hash bits before adding the equality constraint
		for j := 0; j < 256; j++ {
			c.api.AssertIsEqual(blockHashes[i-1][j], parentHashes[i][j])
		}
	}
}

func (c *BNBCircuit) decodeParentHashes() [][256]frontend.Variable {
	hashes := [][256]frontend.Variable{}
	for _, h := range c.Headers {
		parentHash := c.decodeParentHash(h)
		hashes = append(hashes, parentHash)
	}
	return hashes
}

func (c *BNBCircuit) decodeParentHash(header []frontend.Variable) [256]frontend.Variable {
	var parentHashBits [256]frontend.Variable
	parentHash := header[PARENT_HASH_RLP_OFFSET+64 : PARENT_HASH_RLP_OFFSET+64+256]
	copy(parentHashBits[:], parentHash)
	return parentHashBits
}

func (c *BNBCircuit) decodeBlockNumber(hBits []frontend.Variable) frontend.Variable {
	rlpArrayCheck := rlp.ArrayCheck{
		MaxHexLen:            1360,
		MaxFields:            16,
		ArrayPrefixMaxHexLen: 4,
		FieldMinHexLen:       []int{64, 64, 40, 64, 64, 64, 512, 0, 0, 0, 0, 0, 0, 64, 16, 0},
		FieldMaxHexLen:       []int{64, 64, 40, 64, 64, 64, 512, 14, 16, 8, 8, 8, 194, 64, 16, 14},
	}
	nibs := c.bits2Nibs(hBits)
	valid, _, fieldHexLens, fields := rlpArrayCheck.RlpArrayCheck(c.api, nibs)
	c.api.AssertIsEqual(valid, 1)

	// block number
	blockNumLen := fieldHexLens[8]
	blockNumNibs := fields[8]
	shiftCnt := c.api.Sub(16, blockNumLen)
	shifted := rlp.ShiftRight(c.api, 16, 6, blockNumNibs, shiftCnt)
	var blockNumber frontend.Variable = 0
	for i := 0; i < 16; i++ {
		val := c.api.Mul(shifted[i], int(math.Pow(16, float64(15-i))))
		blockNumber = c.api.Add(blockNumber, val)
	}
	return blockNumber
}

func (c *BNBCircuit) decodeBlockNumber(hBits []frontend.Variable) frontend.Variable {
	rlpArrayCheck := rlp.ArrayCheck{
		MaxHexLen:            1400, // Adjusted based on potential additional fields
		MaxFields:            21,   // Updated field count
		ArrayPrefixMaxHexLen: 4,
		FieldMinHexLen:       []int{64, 64, 40, 64, 64, 64, 512, 0, 0, 0, 0, 0, 0, 64, 16, 64, 32, 32, 32, 32, 32},
		FieldMaxHexLen:       []int{64, 64, 40, 64, 64, 64, 512, 14, 16, 8, 8, 8, 194, 64, 16, 64, 32, 32, 32, 32, 32},
	}
	nibs := c.bits2Nibs(hBits)
	valid, _, fieldHexLens, fields := rlpArrayCheck.RlpArrayCheck(c.api, nibs)
	c.api.AssertIsEqual(valid, 1)

	// Adjust the index for block number based on actual field order in BNB Chain
	blockNumLen := fieldHexLens[9] // Example adjustment if Number is the 10th field
	blockNumNibs := fields[9]
	shiftCnt := c.api.Sub(21, blockNumLen)
	shifted := rlp.ShiftRight(c.api, 21, 6, blockNumNibs, shiftCnt)
	var blockNumber frontend.Variable = 0
	for i := 0; i < 21; i++ {
		val := c.api.Mul(shifted[i], int(math.Pow(21, float64(20-i))))
		blockNumber = c.api.Add(blockNumber, val)
	}
	return blockNumber
}

func (c *BNBCircuit) bits2Nibs(bits []frontend.Variable) []frontend.Variable {
	if len(bits)%8 != 0 {
		panic("invalid bit length")
	}
	nibs := []frontend.Variable{}
	for i := 0; i < len(bits); i += 8 {
		n := c.byte2Nibs(bits[i : i+8])
		nibs = append(nibs, n...)
	}
	return nibs
}

func (c *BNBCircuit) byte2Nibs(bits []frontend.Variable) []frontend.Variable {
	if len(bits) != 8 {
		panic("bit len not 8")
	}
	nib0 := c.api.FromBinary(bits[:4]...)
	nib1 := c.api.FromBinary(bits[4:]...)
	return []frontend.Variable{nib1, nib0}
}

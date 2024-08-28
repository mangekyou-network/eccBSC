package headers

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	util "github.com/mangekyou-network/eccBSC/headers/headerutil"
	"github.com/mangekyou-network/eccBSC/log"
)

func TestBNBCircuit(t *testing.T) {
	w := NewBNBChunkProofCircuit()
	circuit := NewBNBChunkProofCircuit()
	err := test.IsSolved(circuit, w, ecc.BN254.ScalarField())
	check(err)

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	check(err)
	fmt.Println("constraints", cs.GetNbConstraints())
}

func NewBNBChunkProofCircuit() *BNBCircuit {
	hs := bnbHeaders()

	headersEncoded, roundIdxs, err := util.EncodeHeaders(hs, false)
	if err != nil {
		fmt.Printf("failed to encode headers: %s\n", err.Error())
		return nil
	}
	root, err := util.ComputeChunkRoot(hs)
	fmt.Printf("chunk root %x\n", root)
	if err != nil {
		log.Errorf("Failed to compute chunk root: %s\n", err.Error())
		return nil
	}
	chunkRoot := util.Hash2FV(root)
	fmt.Printf("prev hash %x\n", hs[0].ParentHash)
	prevHash := util.Hash2FV(hs[0].ParentHash[:])
	eh := hs[len(hs)-1].Hash()
	fmt.Printf("end hash %x\n", eh)
	endHash := util.Hash2FV(eh[:])

	return &BNBCircuit{
		Headers:       headersEncoded,
		ChunkRoot:     chunkRoot,
		PrevHash:      prevHash,
		EndHash:       endHash,
		StartBlockNum: 41746476,
		EndBlockNum:   41746479,
		HashRoundIdxs: roundIdxs,
	}
}

func bnbHeaders() []types.Header {
	var headers []types.Header

	var bloom [256]byte
	bloomBytes := hexutil.MustDecode("0x843266000118b053801100d48a686704120a6c08001440903039a78404553bd40c52126007028414c6480408b23ba0110108988a2400a00921220231112408024d50c440404428082381250f02803229e8334301c044285a041c00e6940164c0435810bb0a4200408140352735503c813c05d4b8218a84201a00009a0acaa507389a108061856ca05f91040d808644900024a541010242b862062744061300b0230f031111941022180502c082400f033c1224189c40400622002b4020c13802ca9004621880861682032c211003108620401082018914b60d51dc430324f8610058600c48a10524a1d812850002133291108fa01008c75dce00e1a0a8082844")
	copy(bloom[:], bloomBytes)
	headers = append(headers, types.Header{
		ParentHash:  common.HexToHash("0x657ef8080378b91a889b3724a011b6160427ddaee819a85379f863ecd249e4c8"),
		UncleHash:   common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
		Coinbase:    [20]byte{},
		Root:        common.HexToHash("0xa16af8cc91934d80d4acce7b09f992fd08f35504b06eeb13b3c22903f66828c6"),
		TxHash:      common.HexToHash("0xa4352c11a901913e906e3a8ce0919cc3f6d9f0e05fa02d1620b9b5978e8d2a25"),
		ReceiptHash: common.HexToHash("0x91c31bc62dcce4ad95e4a4323a98c218ec4efaec0535f1989b434a9844d12822"),
		Bloom:       bloom,
		Difficulty:  new(big.Int).SetBytes(hexutil.MustDecode("0x02")),
		Number:      new(big.Int).SetBytes(hexutil.MustDecode("0x027d002c")),
		GasLimit:    new(big.Int).SetBytes(hexutil.MustDecode("0x08583b00")).Uint64(),
		GasUsed:     new(big.Int).SetBytes(hexutil.MustDecode("0xcbbdc7")).Uint64(),
		Time:        new(big.Int).SetBytes(hexutil.MustDecode("0x66ce8ed1")).Uint64(),
		Extra:       hexutil.MustDecode("0xd88301040a846765746888676f312e32322e32856c696e757800000048fa7b05f8b5831bffffb860ab35dfbed1ac2013665535d27356b55c693b3c400e7171f34ae27b52e3b0b5555a14c72677a40e5ea14c614b28dfb15700d646b12d9d63c629d3b11ed230ff9f17f33e295fddcaa336ae53eb54f5747299f9c09386dc9b8382335ac9a1625618f84c84027d002aa00a15da14b24e493847cd73b1db998f5eb4e3a437b0e9d0a38926bf17d0f3aa3a84027d002ba0657ef8080378b91a889b3724a011b6160427ddaee819a85379f863ecd249e4c8802a988c13c93460cca3be05f7af366ed4cfbadea342d795901dd8025a99a3b6144a16bf2ccf814909239e4c1c3ddcb68946dad8f3a26668e9c85c91e287ca398300"),
		MixDigest:   common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		Nonce:       [8]byte{0, 0, 0, 0, 0, 0, 0, 0}, //0x0000000000000000
		BaseFee:     new(big.Int).SetBytes(hexutil.MustDecode("0x")),
	})
	bloomBytes = hexutil.MustDecode("0xb5ffce97f66e12dab53ddb6a9de93a69e89fc2dbeeb3b3d2147ef366865f3345cf37361eff2fbbd1fbdc6ef23db2e67a1fa8dfe1db9b7b68a54e8609e9f753cd65f6f569bfdebf0af5bd5b69ca7875ffee1ec87dff64ddc7d5f4279ea82b7f272abd92ed17ef94c18533b1459f18f8a7f9b7f7e3aed89fe47735b9d5f7ab259bbbce6dbc2afe96fd3a95e52c12b6c997a6aebc97bb6af71fab28f7f8cc3b686b82c49db15ddd24bccecd7dcc5afedf4ae5af1ca48fe5c99199783ebc6825e7e37ff3b7d247be54ff39b6fb9e30eb9ac6efcdffbbdb5462baffffefee7fb3f97043f628fabd3a6cf5c15dfdbeffc59dadd6d485baa9bfecfafecce04e37502ece")
	copy(bloom[:], bloomBytes)
	headers = append(headers, types.Header{
		ParentHash:  common.HexToHash("0x0d9381eda05afba0fa0ae6d5b0f3b1e689252bd1646a9d970c1a45da03e3879e"),
		UncleHash:   common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
		Coinbase:    [20]byte{},
		Root:        common.HexToHash("0x1ad570ced2a8f8ca304714967e7e38958b8fbee66450cc0013a433302ebe8ab2"),
		TxHash:      common.HexToHash("0xeeff5570d4383898ef4cc040dc0814020f6f0ba13a345d91bf2c00513d2d0220"),
		ReceiptHash: common.HexToHash("0x5e4f50f91bd152a798f4b2cffd62671e7ba3f26324ef6475ef2755be6c6015d3"),
		Bloom:       bloom,
		Difficulty:  new(big.Int).SetBytes(hexutil.MustDecode("0x02")),
		Number:      new(big.Int).SetBytes(hexutil.MustDecode("0x027d002d")),
		GasLimit:    new(big.Int).SetBytes(hexutil.MustDecode("0x084fe2c6")).Uint64(),
		GasUsed:     new(big.Int).SetBytes(hexutil.MustDecode("0x01790ff2")).Uint64(),
		Time:        new(big.Int).SetBytes(hexutil.MustDecode("0x66ce8ed4")).Uint64(),
		Extra:       hexutil.MustDecode("0xd88301040b846765746888676f312e32322e34856c696e757800000048fa7b05f8b5831bffffb8608dcb6ed33360d503194c15d0d791c780a3f1c9aabb17cab58a8d0255889ced6a8510e4a4c61ad8e93e89d3b1407fea2b06eb20f60f1bdb3da58cf4a50d360ac8b9db69051b3a78c7975ed7e71447f0cc758529eb737c2c98dda23bb7324d943af84c84027d002ba0657ef8080378b91a889b3724a011b6160427ddaee819a85379f863ecd249e4c884027d002ca00d9381eda05afba0fa0ae6d5b0f3b1e689252bd1646a9d970c1a45da03e3879e80020a9d81ed55fd8cc2e6e0453ad66420c5689cf8bd2d6dd30691e6c11cf72a8429aa0b3a586b624131ec843a769f24b7cddc4c892803ca6b603160e90c659e5500"),
		MixDigest:   common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		Nonce:       [8]byte{0, 0, 0, 0, 0, 0, 0, 0}, //0x0000000000000000
		BaseFee:     new(big.Int).SetBytes(hexutil.MustDecode("0x")),
	})
	bloomBytes = hexutil.MustDecode("0x7775f748e41c1b1afe1931528260603453c212131ac7a76d380e72ae12679b13c4fb94730b12dc41660e66317d273180698ee403ad0968c832042aebf7a61fcfcc42c43199419e2a613db88b9090906e201844a1f26d5a0706ce6437950544840c0a11ab92c20060ae837c33a0122a888b1c9441f3368e35546c4b71d06a03319a88c0a5e92230cafa950594c4108091416f9705c80a402a29884c59795b002082839610098963e10e08e4e0a3cc07a00836748a1f0050192c722826c42092502d13f56202160a0b3613884738285c0639b4ffa61517229a051165466330f095a672090309a5471ca15dc11c994d43a5c28ac68812a081ce7808d1150e947446")
	copy(bloom[:], bloomBytes)
	headers = append(headers, types.Header{
		ParentHash:  common.HexToHash("0x313580e8b206039e179e8d3613cffa54a952010a6dad0c8452bf945c6297349b"),
		UncleHash:   common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
		Coinbase:    [20]byte{},
		Root:        common.HexToHash("0x63856373db1577eab945e5f4e6dc33117462fba8d6819792978d4059f4b83ad0"),
		TxHash:      common.HexToHash("0xa2e70b6b5588601a697266f1c2ecbcea9f32be79ec32b9e0aa7352606b288458"),
		ReceiptHash: common.HexToHash("0xfe77087f6e915308510e2cdf1b8a5b6e8a3ce5f337ce531eeed8d79e834b7e41"),
		Bloom:       bloom,
		Difficulty:  new(big.Int).SetBytes(hexutil.MustDecode("0x02")),
		Number:      new(big.Int).SetBytes(hexutil.MustDecode("0x027d002e")),
		GasLimit:    new(big.Int).SetBytes(hexutil.MustDecode("0x084792e5")).Uint64(),
		GasUsed:     new(big.Int).SetBytes(hexutil.MustDecode("0x9dc61f")).Uint64(),
		Time:        new(big.Int).SetBytes(hexutil.MustDecode("0x66ce8ed7")).Uint64(),
		Extra:       hexutil.MustDecode("0xd88301040b846765746888676f312e32322e34856c696e757800000048fa7b05f8b5831bffffb860b6a6bec016f7415786b4fa8b2e813eff162e5304db89a6a9972999f8126c952cdac182c359d93c3247f13212f43073140ced2308055c3ff2b3fb70fbd5d8ef984bf701a2be9676c2cbc4baa3474655414dccc01bac660f90d626b3418a88d3bef84c84027d002ca00d9381eda05afba0fa0ae6d5b0f3b1e689252bd1646a9d970c1a45da03e3879e84027d002da0313580e8b206039e179e8d3613cffa54a952010a6dad0c8452bf945c6297349b80f33172a5105795d7c78442f04c446d79df889ee7cb97db586be16cc2a3b09a2663acba892433c5fa08564a14660288c5ee9ea618cc8cb7bf9d0d003a7ee99e0e01"),
		MixDigest:   common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		Nonce:       [8]byte{0, 0, 0, 0, 0, 0, 0, 0}, //0x0000000000000000
		BaseFee:     new(big.Int).SetBytes(hexutil.MustDecode("0x")),
	})
	bloomBytes = hexutil.MustDecode("0x34a4a6420c019500e208ba428e48340088840c08489801482030eac0c76010840131903024071ac44a2cf02070032702810880400c3a38cbc20448a82f222f88c60040500c652a803118cb1980273120e8165447c149781211440081e2e400c44d98903d96038cda000016000a1178880c06245022020e21570c30d384ca36045a040426a64c002c12980c80040c20a91467b685a0966aef21c000511a20807a07801c2b97042121080d33281ad00690604a0090102c42080c8a54608200c02159b05542010a20409081004426420842e840342211120290c130650bd315eaa400b2ec866122c80105ecd14480c0410e55048c2a14d6804ce641082801609842")
	copy(bloom[:], bloomBytes)
	headers = append(headers, types.Header{
		ParentHash:  common.HexToHash("0xd9e185d65ff63e8042ce8ffda976f9bb313423c4fdda6c91295cc20399fb1d23"),
		UncleHash:   common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
		Coinbase:    [20]byte{},
		Root:        common.HexToHash("0xbcad1a388c4528a400a03fcab109f89eefe713dceae16e2fa038423894cb1af7"),
		TxHash:      common.HexToHash("0xa46ff6b9a3a75974f722eaba4f469bdf9e4acd38fea938e3113202cc4a91068a"),
		ReceiptHash: common.HexToHash("0x0d4fb3866397fd8bacdf22ccfa574c6df67690f3240d3504910f40766a63ff31"),
		Bloom:       bloom,
		Difficulty:  new(big.Int).SetBytes(hexutil.MustDecode("0x02")),
		Number:      new(big.Int).SetBytes(hexutil.MustDecode("0x027d002f")),
		GasLimit:    new(big.Int).SetBytes(hexutil.MustDecode("0x084fda76")).Uint64(),
		GasUsed:     new(big.Int).SetBytes(hexutil.MustDecode("0x8e2b16")).Uint64(),
		Time:        new(big.Int).SetBytes(hexutil.MustDecode("0x66ce8eda")).Uint64(),
		Extra:       hexutil.MustDecode("0xd88301040c846765746888676f312e32312e30856c696e757800000048fa7b05f8b5831bffffb8608d2dcd8416be82a489b3d79ce39e6a8209383ebd2e5437b0a1425ced8913a3dd72909297bfb5b6a8fbcdd5dc271fa08802ea66109ff6bc0e917cddd79ce2cb838885aa51384aa444c5283013e506efe47b50da1244e7f2422616a03b1f7e4670f84c84027d002da0313580e8b206039e179e8d3613cffa54a952010a6dad0c8452bf945c6297349b84027d002ea0d9e185d65ff63e8042ce8ffda976f9bb313423c4fdda6c91295cc20399fb1d2380bc71761b56a877c2b8a8109a17397f4c3a2b0e552c8c516eb9de3b36fc4af70f6e6dd6de4a690e478d126f4e5f154aa2a6c350cd6106ef5d82fce8e5cd080acb00"),
		MixDigest:   common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		Nonce:       [8]byte{0, 0, 0, 0, 0, 0, 0, 0}, //0x0000000000000000
		BaseFee:     new(big.Int).SetBytes(hexutil.MustDecode("0x")),
	})

	return headers
}

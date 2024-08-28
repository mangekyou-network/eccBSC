package headers

import (
	"fmt"
	"testing"

	"github.com/PolyhedraZK/ExpanderCompilerCollection"
	"github.com/PolyhedraZK/ExpanderCompilerCollection/test"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestCircuit(t *testing.T) {
	w := NewChunkProofCircuit(4)
	circuit := NewChunkProofCircuit(4)
	err := test.IsSolved(circuit, w, ecc.BN254.ScalarField())
	check(err)

	cs, err := ExpanderCompilerCollection.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	check(err)
	fmt.Println("constraints", cs.GetNbConstraints())
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

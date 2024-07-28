package main

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls12377_fp "github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	sw_bls12377 "github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
)

// variable names must start with a capital letter
type Circuit struct {
	Sigma1 sw_bls12377.G2Affine
	Sigma2 sw_bls12377.G2Affine
	M      frontend.Variable
	G      sw_bls12377.G1Affine `gnark:",public"`
	X      sw_bls12377.G1Affine `gnark:",public"`
	Y      sw_bls12377.G1Affine `gnark:",public"`
	//
	Sn_old_1 frontend.Variable `gnark:",public"`
	Sn_old_2 frontend.Variable `gnark:",public"`
	Cm_new_1 frontend.Variable `gnark:",public"`
	Cm_new_2 frontend.Variable `gnark:",public"`
	//n_old_1
	N_old_1_v   frontend.Variable
	N_old_1_pk  frontend.Variable
	N_old_1_rho frontend.Variable
	N_old_1_r   frontend.Variable
	N_old_1_cm  frontend.Variable
	//n_old_2 frontend.Variable
	N_old_2_v   frontend.Variable
	N_old_2_pk  frontend.Variable
	N_old_2_rho frontend.Variable
	N_old_2_r   frontend.Variable
	N_old_2_cm  frontend.Variable
	//n_new_1 frontend.Variable
	N_new_1_v   frontend.Variable
	N_new_1_pk  frontend.Variable
	N_new_1_rho frontend.Variable
	N_new_1_r   frontend.Variable
	//n_new_2 frontend.Variable
	N_new_2_v   frontend.Variable
	N_new_2_pk  frontend.Variable
	N_new_2_rho frontend.Variable
	N_new_2_r   frontend.Variable
	//
	Sk_old_1 frontend.Variable
	Sk_old_2 frontend.Variable
	//
	R_1_new frontend.Variable
	R_2_new frontend.Variable
}

// e(sig,g2) * e(Hcm,pk) == 1
func (circuit *Circuit) Define(api frontend.API) error {

	/////Proof

	//compute transaction

	// hash function
	mimc_Sn_old_1, _ := mimc.NewMiMC(api)
	mimc_Sn_old_1.Write(circuit.N_old_1_rho)
	mimc_Sn_old_1.Write(circuit.Sk_old_1)
	api.AssertIsEqual(circuit.Sn_old_1, mimc_Sn_old_1.Sum())

	mimc_Sn_old_2, _ := mimc.NewMiMC(api)
	mimc_Sn_old_2.Write(circuit.N_old_2_rho)
	mimc_Sn_old_2.Write(circuit.Sk_old_2)
	api.AssertIsEqual(circuit.Sn_old_2, mimc_Sn_old_2.Sum())

	//Compute rho_new_1
	mimc_rho_new_1, _ := mimc.NewMiMC(api)
	mimc_rho_new_1.Write(mimc_Sn_old_1.Sum())
	mimc_rho_new_1.Write(mimc_Sn_old_2.Sum())
	mimc_rho_new_1.Write(1)

	//Compute rho_new_2
	mimc_rho_new_2, _ := mimc.NewMiMC(api)
	mimc_rho_new_2.Write(mimc_Sn_old_1.Sum())
	mimc_rho_new_2.Write(mimc_Sn_old_2.Sum())
	mimc_rho_new_2.Write(2)

	//Compute Cm_new_1
	mimc_Cm_new_1, _ := mimc.NewMiMC(api)
	mimc_Cm_new_1.Write(circuit.N_new_1_v)
	mimc_Cm_new_1.Write(circuit.N_new_1_pk)
	mimc_Cm_new_1.Write(circuit.N_new_1_rho)
	mimc_Cm_new_1.Write(circuit.R_1_new)

	api.AssertIsEqual(circuit.Cm_new_1, mimc_Cm_new_1.Sum())

	//Compute Cm_new_2
	mimc_Cm_new_2, _ := mimc.NewMiMC(api)
	mimc_Cm_new_2.Write(circuit.N_new_2_v)
	mimc_Cm_new_2.Write(circuit.N_new_2_pk)
	mimc_Cm_new_2.Write(circuit.N_new_2_rho)
	mimc_Cm_new_2.Write(circuit.R_2_new)

	api.AssertIsEqual(circuit.Cm_new_2, mimc_Cm_new_2.Sum())

	//Set tx

	//tx_Sn_old_1 := mimc_Sn_old_1.Sum()
	//tx_Sn_old_2 := mimc_Sn_old_2.Sum()
	//tx_Cm_new_1 := mimc_Cm_new_1.Sum()
	//tx_Cm_new_2 := mimc_Cm_new_2.Sum()

	//Check balance

	var sum_0 = api.Add(circuit.N_old_1_v, circuit.N_old_2_v)
	var sum_1 = api.Add(circuit.N_new_1_v, circuit.N_new_2_v)
	api.AssertIsEqual(sum_0, sum_1)

	//ensure secret and public key are correct
	mimc_pk_1, _ := mimc.NewMiMC(api)
	mimc_pk_1.Write(circuit.Sk_old_1)
	api.AssertIsEqual(circuit.N_old_1_pk, mimc_pk_1.Sum())

	mimc_pk_2, _ := mimc.NewMiMC(api)
	mimc_pk_2.Write(circuit.Sk_old_2)
	api.AssertIsEqual(circuit.N_old_2_pk, mimc_pk_2.Sum())

	//perform signature verification (https://eprint.iacr.org/2015/525.pdf)

	//Compute Y^M
	Y_m := circuit.Y.ScalarMul(api, circuit.Y, circuit.M)
	//Compute X.Y^M
	Y_m.AddAssign(api, circuit.X)

	//pairing check
	sw_bls12377.Pair(api, []sw_bls12377.G1Affine{circuit.G, *Y_m}, []sw_bls12377.G2Affine{circuit.Sigma2, circuit.Sigma1})

	return nil
}

func main() {

	// compiles our circuit into a R1CS
	var circuit Circuit

	ccs, _ := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)

	// groth16 zkSNARK: Setup
	pk, vk, _ := groth16.Setup(ccs)

	// witness definition
	var assignment Circuit

	var v bls12377_fp.Element = bls12377_fp.NewElement(14265327689599303100)

	var value *big.Int = new(big.Int)
	value.SetString("233578398248691099356572568220835526895379068987715365179118596935057653620464273615301663571204657964920925606294", 10)
	var sigma_1_X_A0 = v.SetBigInt(value)

	value.SetString("140913150380207355837477652521042157274541796891053068589147167627541651775299824604154852141315666357241556069118", 10)
	var sigma_1_X_A1 = v.SetBigInt(value)

	value.SetString("63160294768292073209381361943935198908131692476676907196754037919244929611450776219210369229519898517858833747423", 10)
	var sigma_1_Y_A0 = v.SetBigInt(value)

	value.SetString("149157405641012693445398062341192467754805999074082136895788947234480009303640899064710353187729182149407503257491", 10)
	var sigma_1_Y_A1 = v.SetBigInt(value)

	assignment.Sigma1 = sw_bls12377.NewG2Affine(bls12377.G2Affine{
		X: bls12377.E2{
			A0: *sigma_1_X_A0,
			A1: *sigma_1_X_A1,
		},
		Y: bls12377.E2{
			A0: *sigma_1_Y_A0,
			A1: *sigma_1_Y_A1,
		},
	})

	assignment.Sigma2 = sw_bls12377.NewG2Affine(bls12377.G2Affine{
		X: bls12377.E2{
			A0: bls12377_fp.NewElement(14239887584),
			A1: bls12377_fp.NewElement(143313584),
		},
		Y: bls12377.E2{
			A0: bls12377_fp.NewElement(14239887584),
			A1: bls12377_fp.NewElement(143313584),
		},
	})

	assignment.G = sw_bls12377.G1Affine{
		X: "142653276895993031000006916266724128765221908004256063457362569275298456307915314952948497516099307719409858077584",
		Y: "124869013296681382405525099997381943745958348199556996371954051753620340892927007930177100403663166477748695189485",
	}

	assignment.X = sw_bls12377.G1Affine{
		X: "142653276895993031000006916266724128765221908004256063457362569275298456307915314952948497516099307719409858077584",
		Y: "124869013296681382405525099997381943745958348199556996371954051753620340892927007930177100403663166477748695189485",
	}

	assignment.Y = sw_bls12377.G1Affine{
		X: "142653276895993031000006916266724128765221908004256063457362569275298456307915314952948497516099307719409858077584",
		Y: "124869013296681382405525099997381943745958348199556996371954051753620340892927007930177100403663166477748695189485",
	}

	assignment.M = "1" //must be a number
	assignment.Sn_old_1 = "122348998007714828616237113894412717769583193067325270404398719191207139307055435207516609914759983777323349428144"
	assignment.Sn_old_2 = "220978850694229745645586010716037095212048265782664803438098357247377109705181633224750290877598812378669958954865"
	assignment.Cm_new_1 = "27323574403943284234150157512673827756500436267419303499885539850072526124740581409516961451735139490257845276127"
	assignment.Cm_new_2 = "70568487316893770034401504423617896850987140194398771055727022477762723246521765922307203043137154564253666870917"
	assignment.N_old_1_v = "1"
	assignment.N_old_1_pk = "132556077802173429120780851885009383587842856132488300338529381202725734176601080395619451468102083487519691339564"
	assignment.N_old_1_rho = "6"
	assignment.N_old_1_r = "7"
	assignment.N_old_1_cm = "8"
	assignment.N_old_2_v = "1"
	assignment.N_old_2_pk = "251242139134049532650966421212462577004975574167061109923008231265257652926226966151249418016942702500339572913680"
	assignment.N_old_2_rho = "11"
	assignment.N_old_2_r = "12"
	assignment.N_old_2_cm = "13"
	assignment.N_new_1_v = "1"
	assignment.N_new_1_pk = "8176234173808865321053926614999642719724038462869981575850866390361303903314"
	assignment.N_new_1_rho = "79979972923390808883748143571774672950598127596576162390180332298233093091120318324186579648304635210326659993186"
	assignment.N_new_1_r = "17"
	assignment.N_new_2_v = "1"
	assignment.N_new_2_pk = "8176234173808865321053926614999642719724038462869981274850866390361303903314"
	assignment.N_new_2_rho = "207187220453015137872183271299339550802904972140297125743626764478584787013460482269485000343291598801815341152167"
	assignment.N_new_2_r = "22"
	assignment.Sk_old_1 = "24"
	assignment.Sk_old_2 = "25"
	assignment.R_1_new = "26"
	assignment.R_2_new = "27"

	witness, _ := frontend.NewWitness(&assignment, ecc.BW6_761.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	//fmt.Println("Proof:", proof)
	groth16.Verify(proof, vk, publicWitness)
}

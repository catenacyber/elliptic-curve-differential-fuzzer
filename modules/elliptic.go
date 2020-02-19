package main

import "C"

import (
	"crypto/elliptic"
	//	"fmt"
	"math/big"
)

//go build -o elliptic.a -buildmode=c-archive elliptic.go

func getCurve(tlsid uint16) elliptic.Curve {
	switch tlsid {
	case 21:
		return elliptic.P224()
	case 23:
		return elliptic.P256()
	case 24:
		return elliptic.P384()
	case 25:
		return elliptic.P521()
	}
	return nil
}

//export GoProcess
func GoProcess(tlsid uint16, coordx []byte, coordy []byte, scalar []byte, output []byte) int {
	curve := getCurve(tlsid)
	if curve == nil {
		return 1 //FUZZEC_ERROR_UNSUPPORTED
	}

	px := new(big.Int)
	px.SetBytes(coordx)
	py := new(big.Int)
	py.SetBytes(coordy)

	rx, ry := curve.ScalarMult(px, py, scalar)
	if rx.BitLen() == 0 && ry.BitLen() == 0 {
		output[0] = 0
		return 0 //FUZZEC_ERROR_NONE
	}
	res := elliptic.Marshal(curve, rx, ry)
	if len(res) != len(output) {
		return 2 //FUZZEC_ERROR_UNKNOWN
	}
	copy(output, res)
	return 0 //FUZZEC_ERROR_NONE
}

//export GoAdd
func GoAdd(tlsid uint16, coordx []byte, coordy []byte, coord2x []byte, coord2y []byte, output []byte) int {
	curve := getCurve(tlsid)
	if curve == nil {
		return 1 //FUZZEC_ERROR_UNSUPPORTED
	}

	px := new(big.Int)
	px.SetBytes(coordx)
	py := new(big.Int)
	py.SetBytes(coordy)
	qx := new(big.Int)
	qx.SetBytes(coord2x)
	qy := new(big.Int)
	qy.SetBytes(coord2y)

	rx, ry := curve.Add(px, py, qx, qy)
	if rx.BitLen() == 0 && ry.BitLen() == 0 {
		output[0] = 0
		return 0 //FUZZEC_ERROR_NONE
	}
	res := elliptic.Marshal(curve, rx, ry)
	if len(res) != len(output) {
		return 2 //FUZZEC_ERROR_UNKNOWN
	}
	copy(output, res)
	return 0 //FUZZEC_ERROR_NONE
}

func main() {}

// Copyright (c) 2015 The Decred developers
// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chainhash

import "github.com/btcsuite/fastsha256"
import "github.com/jadeblaquiere/btcd/btcec"

// HashB calculates hash(b) and returns the resulting bytes.
func HashB(b []byte) []byte {
	hash := fastsha256.Sum256(b)
	return hash[:]
}

// HashH calculates hash(b) and returns the resulting bytes as a Hash.
func HashH(b []byte) Hash {
	return Hash(fastsha256.Sum256(b))
}

// DoubleHashB calculates hash(hash(b)) and returns the resulting bytes.
func DoubleHashB(b []byte) []byte {
	first := fastsha256.Sum256(b)
	second := fastsha256.Sum256(first[:])
	return second[:]
}

// DoubleHashH calculates hash(hash(b)) and returns the resulting bytes as a
// Hash.
func DoubleHashH(b []byte) Hash {
	first := fastsha256.Sum256(b)
	return Hash(fastsha256.Sum256(first[:]))
}

// ShaMulSha256SH calculates sha256(secp256k1mul(sha256(b))) and returns the resulting bytes
// as a ShaHash.
func ShaMulSha256SH(b []byte) Hash {
	first := fastsha256.Sum256(b)
    _, pub := btcec.PrivKeyFromBytes(btcec.S256(),first[:])
    second := pub.SerializeUncompressed()
    third := fastsha256.Sum256(second[:])
    //fmt.Printf("f,s,t = %s, %s, %s\n", hex.EncodeToString(first[:]), hex.EncodeToString(second), hex.EncodeToString(third[:]))
	return Hash(third)
}

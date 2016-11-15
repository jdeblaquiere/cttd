// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"errors"
	"math/big"
	"time"

	"github.com/jadeblaquiere/cttd/chaincfg/chainhash"
	"github.com/jadeblaquiere/cttd/wire"
)

// These variables are the chain proof-of-work limit parameters for each default
// network.
var (
	// bigOne is 1 represented as a big.Int.  It is defined here to avoid
	// the overhead of creating it multiple times.
	bigOne = big.NewInt(1)

	// ctredNetPowLimit is the highest proof of work value a ciphrtxt block
	// can have for the ciphrtxt red test network.  It is the value 2^248 - 1.
	ctredNetPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 248), bigOne)

	// ctindigoNetPowLimit is the highest proof of work value a ciphrtxt block
	// can have for the ciphrtxt indigo network.  It is the value 2^248 - 1.
	ctindigoNetPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 248), bigOne)
)

// Checkpoint identifies a known good point in the block chain.  Using
// checkpoints allows a few optimizations for old blocks during initial download
// and also prevents forks from old blocks.
//
// Each checkpoint is selected based upon several factors.  See the
// documentation for blockchain.IsCheckpointCandidate for details on the
// selection criteria.
type Checkpoint struct {
	Height int32
	Hash   *chainhash.Hash
}

// Params defines a Bitcoin network by its parameters.  These parameters may be
// used by Bitcoin applications to differentiate networks as well as addresses
// and keys for one network from those intended for use on another network.
type Params struct {
	// Name defines a human-readable identifier for the network.
	Name string

	// Net defines the magic bytes used to identify the network.
	Net wire.BitcoinNet

	// DefaultPort defines the default peer-to-peer port for the network.
	DefaultPort string

	// DNSSeeds defines a list of DNS seeds for the network that are used
	// as one method to discover peers.
	DNSSeeds []string

	// GenesisBlock defines the first block of the chain.
	GenesisBlock *wire.MsgBlock

	// GenesisHash is the starting block hash.
	GenesisHash *chainhash.Hash

	// PowLimit defines the highest allowed proof of work value for a block
	// as a uint256.
	PowLimit *big.Int

	// PowLimitBits defines the highest allowed proof of work value for a
	// block in compact form.
	PowLimitBits uint32

	// CoinbaseMaturity is the number of blocks required before newly mined
	// coins (coinbase transactions) can be spent.
	CoinbaseMaturity uint16

	// SubsidyReductionInterval is the interval of blocks before the subsidy
	// is reduced.
	//SubsidyReductionInterval int32
    SubsidyInitialHalflife int32

	// TargetTimespan is the desired amount of time that should elapse
	// before the block difficulty requirement is examined to determine how
	// it should be changed in order to maintain the desired block
	// generation rate.
	TargetTimespan time.Duration

	// TargetTimePerBlock is the desired amount of time to generate each
	// block.
	TargetTimePerBlock time.Duration

	// RetargetAdjustmentFactor is the adjustment factor used to limit
	// the minimum and maximum amount of adjustment that can occur between
	// difficulty retargets.
	RetargetAdjustmentFactor int64

	// ReduceMinDifficulty defines whether the network should reduce the
	// minimum required difficulty after a long enough period of time has
	// passed without finding a block.  This is really only useful for test
	// networks and should not be set on a main network.
	ReduceMinDifficulty bool

	// MinDiffReductionTime is the amount of time after which the minimum
	// required difficulty should be reduced when a block hasn't been found.
	//
	// NOTE: This only applies if ReduceMinDifficulty is true.
	MinDiffReductionTime time.Duration

	// GenerateSupported specifies whether or not CPU mining is allowed.
	GenerateSupported bool

	// Checkpoints ordered from oldest to newest.
	Checkpoints []Checkpoint

	// Enforce current block version once network has
	// upgraded.  This is part of BIP0034.
	BlockEnforceNumRequired uint64

	// Reject previous block versions once network has
	// upgraded.  This is part of BIP0034.
	BlockRejectNumRequired uint64

	// The number of nodes to check.  This is part of BIP0034.
	BlockUpgradeNumToCheck uint64

	// Mempool parameters
	RelayNonStdTxs bool

	// Address encoding magics
	PubKeyHashAddrID byte // First byte of a P2PKH address
	ScriptHashAddrID byte // First byte of a P2SH address
	PrivateKeyID     byte // First byte of a WIF private key

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID [4]byte
	HDPublicKeyID  [4]byte

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType uint32
    
    // Ciphrtxt Msgstore Service for Header Cache
    CTMsgstoreHost  string
    CTMsgstorePort  string
}

// CTIndigoNetParams defines the network parameters for the ciphrtxt token (CT) ciphertxt-indigo
// network. The Indigo network is the main ciphrtxt network.   
var CTIndigoNetParams = Params{
	Name:        "ctindigonet",
	Net:         wire.CTIndigoNet,
	DefaultPort: "7764",
	DNSSeeds: []string{},

	// Chain parameters
	GenesisBlock:             &ctindigoGenesisBlock,
	GenesisHash:              &ctindigoGenesisHash,
	PowLimit:                 ctindigoNetPowLimit,
	PowLimitBits:             0x1f007fff,
	CoinbaseMaturity:         100,
	//SubsidyReductionInterval: 210000,
    SubsidyInitialHalflife:   10080,
	TargetTimespan:           time.Hour * 2,       // 2 hours
	TargetTimePerBlock:       time.Minute * 1,     // 1 minute
	RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:      false,
	MinDiffReductionTime:     0,
	GenerateSupported:        true,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: nil,

	// Enforce current block version once majority of the network has
	// upgraded.
	// 51% (51 / 100)
	// Reject previous block versions once a majority of the network has
	// upgraded.
	// 75% (75 / 100)
	BlockEnforceNumRequired: 51,
	BlockRejectNumRequired:  75,
	BlockUpgradeNumToCheck:  100,

	// Mempool parameters
	RelayNonStdTxs: true,

	// Address encoding magics
	PubKeyHashAddrID: 0x1c, // starts with C
	ScriptHashAddrID: 0x57, // starts with c
	PrivateKeyID:     0xbb, // starts with 7 (uncompressed) or U (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x02, 0xe8, 0xda, 0x54}, // starts with cprv
	HDPublicKeyID:  [4]byte{0x02, 0xe8, 0xde, 0x8e}, // starts with cpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 99, // ASCII for c
    
    // Ciphrtxt Msgstore Service for Header Cache
    CTMsgstoreHost:  "localhost",
    CTMsgstorePort:  "7754",
}

// RedNetParams defines the network parameters for the ciphrtxt token (CT) ciphertxt-red
// network. The Red network is a test network.   
var CTRedNetParams = Params{
	Name:        "ctrednet",
	Net:         wire.CTRedNet,
	DefaultPort: "17761",
	DNSSeeds:    []string{}, // NOTE: There must NOT be any seeds.

	// Chain parameters
	GenesisBlock:           &ctredGenesisBlock,
	GenesisHash:            &ctredGenesisHash,
	PowLimit:               ctredNetPowLimit,
	PowLimitBits:           0x1f07ffff,
	CoinbaseMaturity:         100,
	//SubsidyReductionInterval: 210000,
    SubsidyInitialHalflife:   10080,
	TargetTimespan:           time.Hour * 2,       // 2 hours
	TargetTimePerBlock:       time.Minute * 1,     // 1 minute
	RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:      false,
	MinDiffReductionTime:     0,
	GenerateSupported:        true,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: nil,

	// Enforce current block version once majority of the network has
	// upgraded.
	// 51% (51 / 100)
	// Reject previous block versions once a majority of the network has
	// upgraded.
	// 75% (75 / 100)
	BlockEnforceNumRequired: 51,
	BlockRejectNumRequired:  75,
	BlockUpgradeNumToCheck:  100,

	// Mempool parameters
	RelayNonStdTxs: true,

	// Address encoding magics
	PubKeyHashAddrID: 0x50, // starts with Z
	ScriptHashAddrID: 0x8e, // starts with z
	PrivateKeyID:     0xa3, // starts with 6 (uncompressed) or R (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0xb2, 0x43, 0x0b}, // starts with zprv
	HDPublicKeyID:  [4]byte{0x04, 0xb2, 0x47, 0x45}, // starts with zpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 99, // ASCII for c

    // Ciphrtxt Msgstore Service for Header Cache
    CTMsgstoreHost:  "localhost",
    CTMsgstorePort:  "17751",
}

var (
	// ErrDuplicateNet describes an error where the parameters for a Bitcoin
	// network could not be set due to the network already being a standard
	// network or previously-registered into this package.
	ErrDuplicateNet = errors.New("duplicate Bitcoin network")

	// ErrUnknownHDKeyID describes an error where the provided id which
	// is intended to identify the network for a hierarchical deterministic
	// private extended key is not registered.
	ErrUnknownHDKeyID = errors.New("unknown hd private extended key bytes")
)

var (
	registeredNets    = make(map[wire.BitcoinNet]struct{})
	pubKeyHashAddrIDs = make(map[byte]struct{})
	scriptHashAddrIDs = make(map[byte]struct{})
	hdPrivToPubKeyIDs = make(map[[4]byte][]byte)
)

// Register registers the network parameters for a Bitcoin network.  This may
// error with ErrDuplicateNet if the network is already registered (either
// due to a previous Register call, or the network being one of the default
// networks).
//
// Network parameters should be registered into this package by a main package
// as early as possible.  Then, library packages may lookup networks or network
// parameters based on inputs and work regardless of the network being standard
// or not.
func Register(params *Params) error {
	if _, ok := registeredNets[params.Net]; ok {
		return ErrDuplicateNet
	}
	registeredNets[params.Net] = struct{}{}
	pubKeyHashAddrIDs[params.PubKeyHashAddrID] = struct{}{}
	scriptHashAddrIDs[params.ScriptHashAddrID] = struct{}{}
	hdPrivToPubKeyIDs[params.HDPrivateKeyID] = params.HDPublicKeyID[:]
	return nil
}

// mustRegister performs the same function as Register except it panics if there
// is an error.  This should only be called from package init functions.
func mustRegister(params *Params) {
	if err := Register(params); err != nil {
		panic("failed to register network: " + err.Error())
	}
}

// IsPubKeyHashAddrID returns whether the id is an identifier known to prefix a
// pay-to-pubkey-hash address on any default or registered network.  This is
// used when decoding an address string into a specific address type.  It is up
// to the caller to check both this and IsScriptHashAddrID and decide whether an
// address is a pubkey hash address, script hash address, neither, or
// undeterminable (if both return true).
func IsPubKeyHashAddrID(id byte) bool {
	_, ok := pubKeyHashAddrIDs[id]
	return ok
}

// IsScriptHashAddrID returns whether the id is an identifier known to prefix a
// pay-to-script-hash address on any default or registered network.  This is
// used when decoding an address string into a specific address type.  It is up
// to the caller to check both this and IsPubKeyHashAddrID and decide whether an
// address is a pubkey hash address, script hash address, neither, or
// undeterminable (if both return true).
func IsScriptHashAddrID(id byte) bool {
	_, ok := scriptHashAddrIDs[id]
	return ok
}

// HDPrivateKeyToPublicKeyID accepts a private hierarchical deterministic
// extended key id and returns the associated public key id.  When the provided
// id is not registered, the ErrUnknownHDKeyID error will be returned.
func HDPrivateKeyToPublicKeyID(id []byte) ([]byte, error) {
	if len(id) != 4 {
		return nil, ErrUnknownHDKeyID
	}

	var key [4]byte
	copy(key[:], id)
	pubBytes, ok := hdPrivToPubKeyIDs[key]
	if !ok {
		return nil, ErrUnknownHDKeyID
	}

	return pubBytes, nil
}

// newHashFromStr converts the passed big-endian hex string into a
// chainhash.Hash.  It only differs from the one available in chainhash in that
// it panics on an error since it will only (and must only) be called with
// hard-coded, and therefore known good, hashes.
func newHashFromStr(hexStr string) *chainhash.Hash {
	hash, err := chainhash.NewHashFromStr(hexStr)
	if err != nil {
		// Ordinarily I don't like panics in library code since it
		// can take applications down without them having a chance to
		// recover which is extremely annoying, however an exception is
		// being made in this case because the only way this can panic
		// is if there is an error in the hard-coded hashes.  Thus it
		// will only ever potentially panic on init and therefore is
		// 100% predictable.
		panic(err)
	}
	return hash
}

func init() {
	// Register all default networks when the package is initialized.
	mustRegister(&CTIndigoNetParams)
	mustRegister(&CTRedNetParams)
}

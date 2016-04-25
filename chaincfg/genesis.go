// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"time"

	"github.com/jadeblaquiere/btcd/wire"
)

// genesisCoinbaseTx is the coinbase transaction for the genesis blocks for
// the main network, regression test network, and test network (version 3).
var genesisCoinbaseTx = wire.MsgTx{
	Version: 1,
	TxIn: []*wire.TxIn{
		{
			PreviousOutPoint: wire.OutPoint{
				Hash:  wire.ShaHash{},
				Index: 0xffffffff,
			},
			SignatureScript: []byte{
				0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, 0x45, /* |.......E| */
				0x54, 0x68, 0x65, 0x20, 0x54, 0x69, 0x6d, 0x65, /* |The Time| */
				0x73, 0x20, 0x30, 0x33, 0x2f, 0x4a, 0x61, 0x6e, /* |s 03/Jan| */
				0x2f, 0x32, 0x30, 0x30, 0x39, 0x20, 0x43, 0x68, /* |/2009 Ch| */
				0x61, 0x6e, 0x63, 0x65, 0x6c, 0x6c, 0x6f, 0x72, /* |ancellor| */
				0x20, 0x6f, 0x6e, 0x20, 0x62, 0x72, 0x69, 0x6e, /* | on brin| */
				0x6b, 0x20, 0x6f, 0x66, 0x20, 0x73, 0x65, 0x63, /* |k of sec|*/
				0x6f, 0x6e, 0x64, 0x20, 0x62, 0x61, 0x69, 0x6c, /* |ond bail| */
				0x6f, 0x75, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, /* |out for |*/
				0x62, 0x61, 0x6e, 0x6b, 0x73, /* |banks| */
			},
			Sequence: 0xffffffff,
		},
	},
	TxOut: []*wire.TxOut{
		{
			Value: 0x12a05f200,
			PkScript: []byte{
				0x41, 0x04, 0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55, /* |A.g....U| */
				0x48, 0x27, 0x19, 0x67, 0xf1, 0xa6, 0x71, 0x30, /* |H'.g..q0| */
				0xb7, 0x10, 0x5c, 0xd6, 0xa8, 0x28, 0xe0, 0x39, /* |..\..(.9| */
				0x09, 0xa6, 0x79, 0x62, 0xe0, 0xea, 0x1f, 0x61, /* |..yb...a| */
				0xde, 0xb6, 0x49, 0xf6, 0xbc, 0x3f, 0x4c, 0xef, /* |..I..?L.| */
				0x38, 0xc4, 0xf3, 0x55, 0x04, 0xe5, 0x1e, 0xc1, /* |8..U....| */
				0x12, 0xde, 0x5c, 0x38, 0x4d, 0xf7, 0xba, 0x0b, /* |..\8M...| */
				0x8d, 0x57, 0x8a, 0x4c, 0x70, 0x2b, 0x6b, 0xf1, /* |.W.Lp+k.| */
				0x1d, 0x5f, 0xac, /* |._.| */
			},
		},
	},
	LockTime: 0,
}

// genesisHash is the hash of the first block in the block chain for the main
// network (genesis block).
var genesisHash = wire.ShaHash([wire.HashSize]byte{ // Make go vet happy.
	0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
	0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
	0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
	0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
})

// genesisMerkleRoot is the hash of the first transaction in the genesis block
// for the main network.
var genesisMerkleRoot = wire.ShaHash([wire.HashSize]byte{ // Make go vet happy.
	0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2,
	0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61,
	0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32,
	0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a,
})

// genesisBlock defines the genesis block of the block chain which serves as the
// public transaction ledger for the main network.
var genesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  wire.ShaHash{},           // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: genesisMerkleRoot,        // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
		Timestamp:  time.Unix(0x495fab29, 0), // 2009-01-03 18:15:05 +0000 UTC
		Bits:       0x1d00ffff,               // 486604799 [00000000ffff0000000000000000000000000000000000000000000000000000]
		Nonce:      0x7c2bac1d,               // 2083236893
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}

// genesisCoinbaseTx is the coinbase transaction for the ciphrtxt red network.
var ctredGenesisCoinbaseTx = wire.MsgTx{
	Version: 1,
	TxIn: []*wire.TxIn{
		{
			PreviousOutPoint: wire.OutPoint{
				Hash:  wire.ShaHash{},
				Index: 0xffffffff,
			},
			SignatureScript: []byte{
                /* 04ffff001d01043f 5468652054696d65732032332f4170722f323031362046424920656e6473207374616e642d6f66662077697468204170706c65206f766572206950686f6e65 */
                0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, 0x3f, /* |.......?| */
                0x54, 0x68, 0x65, 0x20, 0x54, 0x69, 0x6d, 0x65, /* |The Time| */
                0x73, 0x20, 0x32, 0x33, 0x2f, 0x41, 0x70, 0x72, /* |s 23/Apr| */
                0x2f, 0x32, 0x30, 0x31, 0x36, 0x20, 0x46, 0x42, /* |/2016 FB| */
                0x49, 0x20, 0x65, 0x6e, 0x64, 0x73, 0x20, 0x73, /* |I ends s| */
                0x74, 0x61, 0x6e, 0x64, 0x2d, 0x6f, 0x66, 0x66, /* |tand-off| */
                0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x41, 0x70, /* | with Ap| */
                0x70, 0x6c, 0x65, 0x20, 0x6f, 0x76, 0x65, 0x72, /* |ple over| */
                0x20, 0x69, 0x50, 0x68, 0x6f, 0x6e, 0x65,       /* | iPhone|  */
			},
			Sequence: 0xffffffff,
		},
	},
	TxOut: []*wire.TxOut{
		{
			Value: 0x12a05f200,
			PkScript: []byte{
                /* 41 04eb0bd15ca4f9b55247ca49c0a9d1727e01990c6b4c311a32f31bf7844589a9c1e2396c19d0d2c4ff9f7e2f29db55906d1046321cfb05ae94a3fe4c0210392847 ac */
				0x41, 0x04, 0xeb, 0x0b, 0xd1, 0x5c, 0xa4, 0xf9, 
                0xb5, 0x52, 0x47, 0xca, 0x49, 0xc0, 0xa9, 0xd1, 
                0x72, 0x7e, 0x01, 0x99, 0x0c, 0x6b, 0x4c, 0x31, 
                0x1a, 0x32, 0xf3, 0x1b, 0xf7, 0x84, 0x45, 0x89, 
                0xa9, 0xc1, 0xe2, 0x39, 0x6c, 0x19, 0xd0, 0xd2, 
                0xc4, 0xff, 0x9f, 0x7e, 0x2f, 0x29, 0xdb, 0x55, 
                0x90, 0x6d, 0x10, 0x46, 0x32, 0x1c, 0xfb, 0x05, 
                0xae, 0x94, 0xa3, 0xfe, 0x4c, 0x02, 0x10, 0x39, 
                0x28, 0x47, 0xac,
			},
		},
	},
	LockTime: 0,
}

// genesisHash is the hash of the first block in the block chain for the main
// network (genesis block).
var ctredGenesisHash = wire.ShaHash([wire.HashSize]byte{ // Make go vet happy.
	/* 00000000 5ac6d962 7629d93f7 bca4e9a9 22f1d326 be58d519 5b1eaaa 030632f5 */
    0xf5, 0x32, 0x06, 0x03, 0xaa, 0xea, 0xb1, 0x95,
    0x51, 0x8d, 0xe5, 0x6b, 0x32, 0x1d, 0x2f, 0x92,
    0x9a, 0x4e, 0xca, 0x7b, 0x3f, 0xd9, 0x29, 0x76,
    0x62, 0xd9, 0xc6, 0x5a, 0x00, 0x00, 0x00, 0x00,
    
})

// genesisMerkleRoot is the hash of the first transaction in the genesis block
// for the main network.
var ctredGenesisMerkleRoot = wire.ShaHash([wire.HashSize]byte{ // Make go vet happy.
    /* 3e097add a977f9ec 9d85d5ab e4d033f1 eff27940 5df595b8 51100993 4099f5fa */
	0xfa, 0xf5, 0x99, 0x40, 0x93, 0x09, 0x10, 0x51, 
    0xb8, 0x95, 0xf5, 0x5d, 0x40, 0x79, 0xf2, 0xef, 
    0xf1, 0x33, 0xd0, 0xe4, 0xab, 0xd5, 0x85, 0x9d, 
    0xec, 0xf9, 0x77, 0xa9, 0xdd, 0x7a, 0x09, 0x3e,
})

// genesisBlock defines the genesis block of the block chain which serves as the
// public transaction ledger for the main network.
var ctredGenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  wire.ShaHash{},           // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: ctredGenesisMerkleRoot,        // 3e097adda977f9ec9d85d5abe4d033f1eff279405df595b8511009934099f5fa
		Timestamp:  time.Unix(0x571e55ab, 0), // 2016-04-25 17:36:43 +0000 UTC
		Bits:       0x1d00ffff,               // 486604799 [00000000ffff0000000000000000000000000000000000000000000000000000]
		Nonce:      0xe49b1397,               // 3835368343
	},
	Transactions: []*wire.MsgTx{&ctredGenesisCoinbaseTx},
}

// regTestGenesisHash is the hash of the first block in the block chain for the
// regression test network (genesis block).
var regTestGenesisHash = wire.ShaHash([wire.HashSize]byte{ // Make go vet happy.
	0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59,
	0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
	0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f,
	0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
})

// regTestGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the regression test network.  It is the same as the merkle root for
// the main network.
var regTestGenesisMerkleRoot = genesisMerkleRoot

// regTestGenesisBlock defines the genesis block of the block chain which serves
// as the public transaction ledger for the regression test network.
var regTestGenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  wire.ShaHash{},           // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: regTestGenesisMerkleRoot, // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
		Timestamp:  time.Unix(1296688602, 0), // 2011-02-02 23:16:42 +0000 UTC
		Bits:       0x207fffff,               // 545259519 [7fffff0000000000000000000000000000000000000000000000000000000000]
		Nonce:      2,
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}

// testNet3GenesisHash is the hash of the first block in the block chain for the
// test network (version 3).
var testNet3GenesisHash = wire.ShaHash([wire.HashSize]byte{ // Make go vet happy.
	0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71,
	0x08, 0xf4, 0xa3, 0x0f, 0xd9, 0xce, 0xc3, 0xae,
	0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad,
	0x01, 0xea, 0x33, 0x09, 0x00, 0x00, 0x00, 0x00,
})

// testNet3GenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the test network (version 3).  It is the same as the merkle root
// for the main network.
var testNet3GenesisMerkleRoot = genesisMerkleRoot

// testNet3GenesisBlock defines the genesis block of the block chain which
// serves as the public transaction ledger for the test network (version 3).
var testNet3GenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  wire.ShaHash{},            // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: testNet3GenesisMerkleRoot, // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
		Timestamp:  time.Unix(1296688602, 0),  // 2011-02-02 23:16:42 +0000 UTC
		Bits:       0x1d00ffff,                // 486604799 [00000000ffff0000000000000000000000000000000000000000000000000000]
		Nonce:      0x18aea41a,                // 414098458
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}

// simNetGenesisHash is the hash of the first block in the block chain for the
// simulation test network.
var simNetGenesisHash = wire.ShaHash([wire.HashSize]byte{ // Make go vet happy.
	0xf6, 0x7a, 0xd7, 0x69, 0x5d, 0x9b, 0x66, 0x2a,
	0x72, 0xff, 0x3d, 0x8e, 0xdb, 0xbb, 0x2d, 0xe0,
	0xbf, 0xa6, 0x7b, 0x13, 0x97, 0x4b, 0xb9, 0x91,
	0x0d, 0x11, 0x6d, 0x5c, 0xbd, 0x86, 0x3e, 0x68,
})

// simNetGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the simulation test network.  It is the same as the merkle root for
// the main network.
var simNetGenesisMerkleRoot = genesisMerkleRoot

// simNetGenesisBlock defines the genesis block of the block chain which serves
// as the public transaction ledger for the simulation test network.
var simNetGenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  wire.ShaHash{},           // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: simNetGenesisMerkleRoot,  // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
		Timestamp:  time.Unix(1401292357, 0), // 2014-05-28 15:52:37 +0000 UTC
		Bits:       0x207fffff,               // 545259519 [7fffff0000000000000000000000000000000000000000000000000000000000]
		Nonce:      2,
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}

// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"time"

	"github.com/jadeblaquiere/ctcd/chaincfg/chainhash"
	"github.com/jadeblaquiere/ctcd/ciphrtxt"
	"github.com/jadeblaquiere/ctcd/wire"
)

// ctindigoGenesisCoinbaseTx is the coinbase transaction for the genesis blocks
// for the ciphrtxt indigo network.
var ctindigoGenesisCoinbaseTx = wire.MsgTx{
    Version: 1,
    TxIn: []*wire.TxIn{
        {
            PreviousOutPoint: wire.OutPoint{
                Hash:  chainhash.Hash{},
                Index: 0xffffffff,
            },
            SignatureScript: []byte{
                0x04, 0xff, 0x3f, 0x00, 0x1f, 0x01, 0x04, 0x4c, /* |..?....L| */
                0x55, 0x4e, 0x65, 0x77, 0x20, 0x59, 0x6f, 0x72, /* |UNew Yor| */
                0x6b, 0x20, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x20, /* |k Times | */
                0x32, 0x32, 0x2f, 0x53, 0x65, 0x70, 0x2f, 0x32, /* |22/Sep/2| */
                0x30, 0x31, 0x36, 0x20, 0x59, 0x61, 0x68, 0x6f, /* |016 Yaho| */
                0x6f, 0x20, 0x53, 0x61, 0x79, 0x73, 0x20, 0x48, /* |o Says H| */
                0x61, 0x63, 0x6b, 0x65, 0x72, 0x73, 0x20, 0x53, /* |ackers S| */
                0x74, 0x6f, 0x6c, 0x65, 0x20, 0x44, 0x61, 0x74, /* |tole Dat| */
                0x61, 0x20, 0x6f, 0x6e, 0x20, 0x35, 0x30, 0x30, /* |a on 500| */
                0x20, 0x4d, 0x69, 0x6c, 0x6c, 0x69, 0x6f, 0x6e, /* | Million| */
                0x20, 0x55, 0x73, 0x65, 0x72, 0x73, 0x20, 0x69, /* | Users i| */
                0x6e, 0x20, 0x32, 0x30, 0x31, 0x34, /* |n 2014| */
            },
            Sequence: 0xffffffff,
        },
    },
    TxOut: []*wire.TxOut{
        {
            Value: 0x17d7840000,
            PkScript: []byte{
                0x41, 0x04, 0xd2, 0x19, 0x60, 0x6a, 0xc1, 0x4a, /* |A...`j.J| */
                0xfe, 0x9a, 0x5a, 0xbd, 0xac, 0x33, 0x06, 0xf4, /* |..Z..3..| */
                0x2d, 0x15, 0xb7, 0x93, 0x77, 0x67, 0xde, 0x40, /* |-...wg.@| */
                0x01, 0x3a, 0x9e, 0x74, 0x25, 0xfe, 0xb7, 0x9f, /* |.:.t%...| */
                0xdf, 0x30, 0x91, 0x16, 0x44, 0x5d, 0x0a, 0xf3, /* |.0..D]..| */
                0xe6, 0x97, 0x96, 0x35, 0x87, 0x70, 0xda, 0x76, /* |...5.p.v| */
                0xbb, 0xe6, 0xd2, 0x95, 0xac, 0x3e, 0x2b, 0x2a, /* |.....>+*| */
                0x19, 0xc7, 0x9e, 0x28, 0x70, 0x67, 0x64, 0x7d, /* |...(pgd}| */
                0xd5, 0x7a, 0xac, /* |.z.| */
            },
        },
    },
    LockTime: 0,
}

// ctindigoGenesisHash is the hash of the first block in the block chain for the
// ciphrtxt indigo network (genesis block).
var ctindigoGenesisHash = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
    0x71, 0x90, 0xb1, 0x07, 0xfa, 0x4f, 0x09, 0x9d, 
    0x6d, 0xe9, 0x32, 0x2f, 0x2b, 0x86, 0xa8, 0xdf, 
    0xf6, 0xb5, 0xf4, 0xca, 0xd7, 0x04, 0xbf, 0x22, 
    0x54, 0xd8, 0xa4, 0x55, 0x0b, 0x08, 0x00, 0x00, 
})

// ctindigoGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the ciphrtxt indigo network.
var ctindigoGenesisMerkleRoot = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
    0xc3, 0xb9, 0x8b, 0x18, 0xeb, 0x9f, 0x18, 0xb7, 
    0x19, 0xf0, 0x85, 0xb6, 0xbb, 0xfa, 0xf8, 0xac, 
    0x0b, 0x2b, 0x53, 0xbd, 0x81, 0xa9, 0x51, 0x7c, 
    0x95, 0x21, 0x9e, 0x20, 0x70, 0xec, 0x5b, 0xda, 
})

// ctindigoGenesisBlock defines the genesis block of the block chain which serves
// as the public transaction ledger for the ciphrtxt indigo network.
var ctindigoGenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    101,
		PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: ctindigoGenesisMerkleRoot,        // da5bec70209e21957c51a981bd532b0bacf8fabbb685f019b7189feb188bb9c3
		Timestamp:  time.Unix(0x5812d201, 0), // Fri Oct 28 04:20:17 2016
		Bits:       0x1f003fff,               // 520110079 [00003fff00000000000000000000000000000000000000000000000000000000]
     NonceHeaderA: [ciphrtxt.MessageHeaderLengthV2]byte{
         0x4d, 0x02, 0x00, 0x00, 0x58, 0x13, 0x3b, 0xd6, /* |M...X.;.| */
         0x58, 0x1c, 0x76, 0x56, 0x03, 0x45, 0xe5, 0x06, /* |X.vV.E..| */
         0x67, 0x65, 0x3a, 0xc5, 0xb5, 0xee, 0x71, 0x9f, /* |ge:...q.| */
         0xc3, 0xb9, 0xc4, 0xb6, 0xb8, 0x3a, 0x2f, 0x8b, /* |.....:/.| */
         0xa7, 0x22, 0xdd, 0xa5, 0x70, 0xcc, 0xd8, 0xf7, /* |."..p...| */
         0xa7, 0xad, 0x14, 0x56, 0x5e, 0x03, 0xf3, 0x8b, /* |...V^...| */
         0x31, 0xa3, 0x73, 0x5d, 0x7f, 0xdb, 0xa8, 0x90, /* |1.s]...| */
         0x28, 0x3f, 0x64, 0x6f, 0xee, 0xa3, 0x10, 0x71, /* |(?do...q| */
         0x00, 0x62, 0xba, 0x72, 0x4d, 0x6a, 0xe6, 0x3b, /* |.b.rMj.;| */
         0xcc, 0xe2, 0x07, 0xe8, 0x4e, 0x28, 0x02, 0xfd, /* |....N(..| */
         0xd7, 0x4a, 0x87, 0x41, 0x35, 0x82, 0x74, 0xa7, /* |.J.A5.t.| */
         0xb0, 0x10, 0xd6, 0x35, 0xd8, 0xa3, 0xfd, 0x4d, /* |...5...M| */
         0x87, 0x88, 0x35, 0x66, 0x6f, 0x7a, 0x27, 0x33, /* |..5foz'3| */
         0x1c, 0x3b, 0x5a, 0x84, 0x55, 0xae, 0x7b, 0x00, /* |.;Z.U.{.| */
         0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, /* |........| */
         0x00, 0x00, 0x00, 0x77, 0x10, 0x6b, 0xc9, 0x2b, /* |...w.k.+| */
         0xbb, 0xa3, 0x15, 0xe8, 0x60, 0x5b, 0x73, 0xf6, /* |....`[s.| */
         0xe9, 0x1f, 0x10, 0x48, 0xe3, 0x5a, 0xce, 0x9f, /* |...H.Z..| */
         0x83, 0x94, 0x41, 0x2f, 0xbe, 0xda, 0xa7, 0x2e, /* |..A/....| */
         0x9d, 0x63, 0x80, 0x08, 0x93, 0xcd, 0x3c, 0x57, /* |.c....<W| */
         0xdf, 0x62, 0x44, 0xd7, 0xcb, 0x52, 0xe7, 0x0c, /* |.bD..R..| */
         0x80, 0x92, 0x34, 0xcf, 0xac, 0x98, 0x78, 0x9d, /* |..4...x.| */
         0xee, 0xa2, 0x70, 0x7f, 0xe0, 0x2c, 0x44, 0x13, /* |..p.,D.| */
         0x1c, 0xb3, 0xe8, 0x00, 0x00, 0x01, 0xad, 0x7c, /* |.......|| */
     },
     NonceHeaderB: [ciphrtxt.MessageHeaderLengthV2]byte{
         0x4d, 0x02, 0x00, 0x00, 0x58, 0x13, 0x09, 0xc2, /* |M...X...| */
         0x58, 0x1c, 0x44, 0x42, 0x02, 0x1d, 0x28, 0x26, /* |X.DB..(&| */
         0x0d, 0xe4, 0x92, 0x7d, 0x2f, 0x4a, 0x45, 0x3d, /* |...}/JE=| */
         0x92, 0xdd, 0xb7, 0x5f, 0xb9, 0x65, 0xdd, 0x3f, /* |..._.e.?| */
         0x5f, 0x81, 0xf9, 0x19, 0x1f, 0xe1, 0x08, 0x6e, /* |_......n| */
         0x82, 0x95, 0xf7, 0xae, 0x6f, 0x02, 0x75, 0x76, /* |....o.uv| */
         0x2a, 0x52, 0xd2, 0x67, 0x0d, 0x5a, 0x49, 0x7c, /* |*R.g.ZI|| */
         0x57, 0x1a, 0x78, 0x5e, 0x4d, 0x1f, 0x5c, 0x67, /* |W.x^M.\g| */
         0x5e, 0x87, 0x3f, 0x31, 0x25, 0x44, 0x42, 0xa9, /* |^.?1%DB.| */
         0xe7, 0x71, 0x4c, 0xb3, 0xdb, 0x14, 0x02, 0x8b, /* |.qL.....| */
         0xfc, 0x56, 0x51, 0x29, 0xac, 0x52, 0x3a, 0x61, /* |.VQ).R:a| */
         0x4e, 0x89, 0x4f, 0xc2, 0xf5, 0xa2, 0x75, 0x7a, /* |N.O...uz| */
         0xb0, 0x77, 0x2e, 0x35, 0xbe, 0xbf, 0x7b, 0xdd, /* |.w.5..{.| */
         0x45, 0xcc, 0xf1, 0x24, 0x24, 0x8b, 0x28, 0x00, /* |E..$$.(.| */
         0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, /* |..0.....| */
         0x00, 0x00, 0x00, 0x6a, 0x4b, 0x31, 0x06, 0x8f, /* |...jK1..| */
         0x21, 0xaa, 0x79, 0xe2, 0x48, 0xdf, 0x83, 0x1f, /* |!.y.H...| */
         0xa0, 0x92, 0xc8, 0xbf, 0x59, 0x24, 0x0f, 0x67, /* |....Y$.g| */
         0x7e, 0x56, 0xd6, 0xdc, 0x79, 0xaf, 0x63, 0xf6, /* |~V..y.c.| */
         0x40, 0xf2, 0x1a, 0xad, 0xd4, 0x04, 0x59, 0xbb, /* |@.....Y.| */
         0x1e, 0xaf, 0xc1, 0x78, 0xee, 0xb0, 0x6d, 0xa1, /* |...x..m.| */
         0x73, 0x81, 0x11, 0xda, 0x7b, 0x66, 0x90, 0x44, /* |s...{f.D| */
         0x10, 0xe2, 0x07, 0x14, 0x9c, 0xdd, 0x4d, 0xf8, /* |......M.| */
         0x86, 0x12, 0x02, 0x00, 0x00, 0x00, 0x8d, 0x30, /* |.......0| */
     },
	},
	Transactions: []*wire.MsgTx{&ctindigoGenesisCoinbaseTx},
}


// ctredGenesisCoinbaseTx is the coinbase transaction for the genesis blocks
// for the ciphrtxt red network.
var ctredGenesisCoinbaseTx = wire.MsgTx{
    Version: 1,
    TxIn: []*wire.TxIn{
        {
            PreviousOutPoint: wire.OutPoint{
                Hash:  chainhash.Hash{},
                Index: 0xffffffff,
            },
            SignatureScript: []byte{
                0x04, 0xff, 0xff, 0x07, 0x1f, 0x01, 0x04, 0x3f, /* |.......?| */
                0x54, 0x68, 0x65, 0x20, 0x54, 0x69, 0x6d, 0x65, /* |The Time| */
                0x73, 0x20, 0x32, 0x33, 0x2f, 0x41, 0x70, 0x72, /* |s 23/Apr| */
                0x2f, 0x32, 0x30, 0x31, 0x36, 0x20, 0x46, 0x42, /* |/2016 FB| */
                0x49, 0x20, 0x65, 0x6e, 0x64, 0x73, 0x20, 0x73, /* |I ends s| */
                0x74, 0x61, 0x6e, 0x64, 0x2d, 0x6f, 0x66, 0x66, /* |tand-off| */
                0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x41, 0x70, /* | with Ap| */
                0x70, 0x6c, 0x65, 0x20, 0x6f, 0x76, 0x65, 0x72, /* |ple over| */
                0x20, 0x69, 0x50, 0x68, 0x6f, 0x6e, 0x65, /* | iPhone| */
            },
            Sequence: 0xffffffff,
        },
    },
    TxOut: []*wire.TxOut{
        {
            Value: 0x17d7840000,
            PkScript: []byte{
                0x41, 0x04, 0xc1, 0x40, 0x4e, 0xaa, 0x79, 0xd6, /* |A..@N.y.| */
                0x4a, 0x1b, 0x81, 0xe5, 0xcd, 0x76, 0x5f, 0xe8, /* |J....v_.| */
                0x2a, 0xfb, 0x6a, 0x33, 0x9a, 0xb2, 0x62, 0x48, /* |*.j3..bH| */
                0x57, 0x1a, 0x83, 0x76, 0x98, 0x48, 0x8b, 0xa6, /* |W..v.H..| */
                0xba, 0xc4, 0xe9, 0x1d, 0x5d, 0x65, 0x4d, 0xa3, /* |....]eM.| */
                0xd0, 0x5b, 0x97, 0x7a, 0x52, 0xd8, 0x6c, 0x4e, /* |.[.zR.lN| */
                0x78, 0x58, 0x92, 0xeb, 0xd9, 0xec, 0xe2, 0xd1, /* |xX......| */
                0xc2, 0xcd, 0x2e, 0xab, 0x42, 0x36, 0x47, 0x7a, /* |....B6Gz| */
                0x78, 0xea, 0xac, /* |x..| */
            },
        },
    },
    LockTime: 0,
}

// ctredGenesisHash is the hash of the first block in the block chain for the
// ciphrtxt red network (genesis block).
var ctredGenesisHash = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
    0xd8, 0x27, 0xb4, 0xad, 0x0d, 0x08, 0x12, 0x58, 
    0xeb, 0x30, 0x73, 0x4a, 0x00, 0xbf, 0x17, 0x73, 
    0xa6, 0x5b, 0xa0, 0x21, 0xaf, 0x36, 0x49, 0x6e, 
    0x70, 0x53, 0xa6, 0x94, 0xa8, 0xf5, 0x06, 0x00, 
})

// ctredGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the ciphrtxt red network.
var ctredGenesisMerkleRoot = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
    0xee, 0xc9, 0x63, 0xc1, 0xad, 0xef, 0x6a, 0x6b, 
    0x10, 0x9a, 0x2c, 0x53, 0xb2, 0x20, 0x9b, 0x56, 
    0xe0, 0x2b, 0xac, 0xb9, 0x05, 0xb4, 0xf2, 0xe0, 
    0x6c, 0x84, 0x4b, 0x2d, 0x5f, 0x65, 0x6f, 0x32, 
})

// ctredGenesisBlock defines the genesis block of the block chain which serves
// as the public transaction ledger for the ciphrtxt red network.
var ctredGenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    101,
		PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: ctredGenesisMerkleRoot,        // 326f655f2d4b846ce0f2b405b9ac2be0569b20b2532c9a106b6aefadc163c9ee
		Timestamp:  time.Unix(0x57fedf94, 0), // Thu Oct 13 01:12:52 2016
		Bits:       0x1f07ffff,               // 520617983 [0007ffff00000000000000000000000000000000000000000000000000000000]
     NonceHeaderA: [ciphrtxt.MessageHeaderLengthV2]byte{
         0x4d, 0x02, 0x00, 0x00, 0x58, 0x13, 0x61, 0xd0, /* |M...X.a.| */
         0x58, 0x1c, 0x9c, 0x50, 0x03, 0x60, 0x75, 0x94, /* |X..P.`u.| */
         0x4f, 0x4a, 0x2f, 0x10, 0x8b, 0xdf, 0x15, 0x22, /* |OJ/...."| */
         0xbd, 0x20, 0xec, 0x15, 0x66, 0xc4, 0xfd, 0x65, /* |. ..f..e| */
         0xa0, 0xed, 0xea, 0x9d, 0x7f, 0x24, 0xc1, 0x63, /* |....$.c| */
         0xb2, 0xeb, 0xf2, 0x93, 0x8f, 0x02, 0x04, 0x48, /* |.......H| */
         0x0c, 0x57, 0xa1, 0xe3, 0xdf, 0x3d, 0x33, 0xc8, /* |.W...=3.| */
         0x15, 0x13, 0x98, 0x1e, 0x00, 0x55, 0x62, 0x63, /* |.....Ubc| */
         0x23, 0x5c, 0x83, 0xc9, 0x1a, 0xb1, 0x55, 0x41, /* |#\....UA| */
         0x6a, 0xa4, 0xfd, 0x35, 0x14, 0x82, 0x02, 0x2b, /* |j..5...+| */
         0x60, 0x95, 0xf7, 0x63, 0xca, 0x0e, 0x5f, 0xde, /* |`..c.._.| */
         0x8b, 0x89, 0xa1, 0x94, 0x56, 0x4c, 0x8f, 0x5e, /* |....VL.^| */
         0x1d, 0x73, 0x01, 0x8d, 0x54, 0xcf, 0x7a, 0x52, /* |.s..T.zR| */
         0xd8, 0x87, 0xe4, 0x2d, 0x97, 0x32, 0xee, 0x00, /* |...-.2..| */
         0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, /* |........| */
         0x00, 0x00, 0x00, 0xc4, 0x22, 0xee, 0xbc, 0xc2, /* |...."...| */
         0xf2, 0x8c, 0x3d, 0xe9, 0x5c, 0x11, 0x2b, 0x38, /* |..=.\.+8| */
         0xd3, 0x2d, 0xfa, 0x24, 0x99, 0x43, 0x60, 0xd7, /* |.-.$.C`.| */
         0xea, 0x55, 0xb8, 0xd8, 0x76, 0x48, 0x29, 0x1b, /* |.U..vH).| */
         0x35, 0x69, 0x04, 0x62, 0xf8, 0x72, 0xf9, 0xa3, /* |5i.b.r..| */
         0x78, 0x29, 0x17, 0xd5, 0x54, 0x32, 0x7c, 0x47, /* |x)..T2|G| */
         0x46, 0x82, 0xb2, 0xd6, 0xab, 0x4a, 0xc5, 0xe7, /* |F....J..| */
         0x97, 0x65, 0x72, 0x27, 0x56, 0x00, 0x86, 0x2f, /* |.er'V../| */
         0xbf, 0x0b, 0x18, 0x00, 0x00, 0x00, 0x44, 0x82, /* |......D.| */
     },
     NonceHeaderB: [ciphrtxt.MessageHeaderLengthV2]byte{
         0x4d, 0x02, 0x00, 0x00, 0x58, 0x12, 0xfd, 0xb8, /* |M...X...| */
         0x58, 0x1c, 0x38, 0x38, 0x03, 0xea, 0xd8, 0x8a, /* |X.88....| */
         0x0e, 0x44, 0xf7, 0xe8, 0x6e, 0x2a, 0xb0, 0x88, /* |.D..n*..| */
         0x26, 0x55, 0xf9, 0x39, 0x22, 0x4a, 0xd7, 0xc7, /* |&U.9"J..| */
         0x82, 0x4f, 0x1b, 0xc7, 0x07, 0x88, 0x82, 0x68, /* |.O.....h| */
         0x3d, 0x54, 0xb0, 0x0b, 0xd6, 0x02, 0xb2, 0x18, /* |=T......| */
         0xd9, 0x23, 0x6c, 0x1e, 0xdd, 0xf5, 0xb4, 0xcc, /* |.#l.....| */
         0xe5, 0xca, 0xaf, 0xb4, 0xec, 0x3a, 0x6c, 0xd1, /* |.....:l.| */
         0x4d, 0xb1, 0x08, 0x14, 0x94, 0x0b, 0xea, 0xee, /* |M.......| */
         0x02, 0x0e, 0x94, 0x7c, 0x4d, 0x1b, 0x02, 0x20, /* |...|M.. | */
         0xe7, 0xfb, 0xf7, 0x09, 0x27, 0x41, 0x83, 0xc1, /* |....'A..| */
         0x56, 0xd9, 0xf0, 0x70, 0x53, 0x7a, 0x00, 0x88, /* |V..pSz..| */
         0x06, 0x75, 0xf5, 0x6e, 0x4e, 0x03, 0x77, 0xed, /* |.u.nN.w.| */
         0xbd, 0x83, 0x66, 0x75, 0xe9, 0xa7, 0x10, 0x00, /* |..fu....| */
         0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, /* |........| */
         0x00, 0x00, 0x00, 0xc6, 0xe8, 0x55, 0x3d, 0xef, /* |.....U=.| */
         0xe3, 0x90, 0x17, 0xdc, 0xb7, 0xea, 0x6f, 0x13, /* |......o.| */
         0xf3, 0x51, 0xd5, 0x07, 0x01, 0xfd, 0xa5, 0x17, /* |.Q......| */
         0x3d, 0x35, 0xbb, 0x9f, 0x04, 0xd0, 0xe7, 0x80, /* |=5......| */
         0x2a, 0x9b, 0x59, 0x6e, 0xfc, 0x76, 0x1c, 0x8e, /* |*.Yn.v..| */
         0x67, 0x8f, 0x09, 0x96, 0xcf, 0x62, 0x60, 0xea, /* |g....b`.| */
         0x72, 0x5e, 0x9a, 0x6c, 0x8b, 0xa6, 0x51, 0x9a, /* |r^.l..Q.| */
         0xc6, 0x65, 0xda, 0x3c, 0xda, 0xde, 0x13, 0xda, /* |.e.<....| */
         0xd1, 0xb9, 0xd2, 0x00, 0x00, 0x00, 0x4a, 0xf3, /* |......J.| */
     },
	},
	Transactions: []*wire.MsgTx{&ctredGenesisCoinbaseTx},
}

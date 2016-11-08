// Copyright (c) 2016, Joseph deBlaquiere <jadeblaquiere@yahoo.com>
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
//
// * Neither the name of ciphrtxt nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package ciphrtxt

import (
    "bytes"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "encoding/binary"
    "fmt"
    "strconv"
    "strings"
    "time"
)

const MessageHeaderLengthV1 =  5 + 1 + // "M0100" + ":"
                      8 + 1 + // time(32 bit hex) + ":"
                      8 + 1 + // expire(32 bit hex) + ":"
                     66 + 1 + // I (256-bit point, compressed hex) + ":"
                     66 + 1 + // I (256-bit point, compressed hex) + ":"
                     66 + 1 + // I (256-bit point, compressed hex) + ":"
                     64 + 1 + // r (256-bit integer, hex) + ":"
                     64       // s (256-bit integer, hex)

type SerializedMessageHeaderV1 [MessageHeaderLengthV1]byte

// V2 message header format:
// "M\0x02\0x00\0x00" =>  4 bytes => Message File, v 2.00 / 0200
// Message Time       =>  4 bytes => 32-bit unsigned UNIX time
// Message Expire     =>  4 bytes => 32-bit unsigned UNIX time
// I (point)          => 33 bytes => 256-bit ECC point, compressed
// J (point)          => 33 bytes => 256-bit ECC point, compressed
// K (point)          => 33 bytes => 256-bit ECC point, compressed
// blocklength        =>  4 bytes => 32 bit block length
// reserved           =>  8 bytes => 64 bits reserved (should be zero)
// short (subtotal)   =============> 123 bytes (164 bytes in base64 encoding)
// r, s               => 64 bytes => 2*256-bit ECDSA signature
// nonce              =>  5 bytes => 40-bit Nonce
// sig + nonce        =============> 69 bytes (92 bytes in base64 encoding)
//                      192 bytes (256 bytes in base64)
// the encrypted message is signed along with the short header and then the
// nonce is calculated to ensure the hash of the long header has nbits zeros
// (see also Authenticated Encryption with Additional Data, AEAD, and Hashcash)

//const ShortMessageHeaderLengthV2 = (4+4+4+33+33+33+4+8)   
const ShortMessageHeaderLengthV2 = (123)   
//const ShortMessageHeaderLengthB64V2 = ((ShortMessageHeaderLengthV2 * 4) / 3)
const ShortMessageHeaderLengthB64V2 = (164)

//const MessageHeaderLengthV2 = (ShortMessageHeaderLengthV2+32+32+5)   
const MessageHeaderLengthV2 = (192)   
//const MessageHeaderLengthB64V2 = ((MessageHeaderLengthV2 * 4) / 3)
const MessageHeaderLengthB64V2 = (256)

type SerializedMessageHeaderV2 [MessageHeaderLengthB64V2]byte
type BinaryMessageHeaderV2 [MessageHeaderLengthV2]byte

// RawMessageHeader treats larger data objects (EC Points, big integers) as strings
// instead of parsing them to their numerical value

type RawMessageHeader struct {
    version string
    time    uint32
    expire  uint32
    I       string
    J       string
    K       string
    blocklen    uint32
    reserved    uint64
    r       string
    s       string
    nonce   uint64
}

func (z *RawMessageHeader) deserializeV1(s string) *RawMessageHeader {
    var t64 uint64
    var d = strings.Split(s, ":")
    if len(d) != 8 || strings.Compare(d[0],"M0100") != 0 {
        return nil
    }
    z.version = "0100"
    t64, _ = strconv.ParseUint(d[1], 16, 32)
    z.time = uint32(t64)
    t64, _ = strconv.ParseUint(d[2], 16, 32)
    z.expire = uint32(t64)
    z.I = d[3]
    z.J = d[4]
    z.K = d[5]
    z.r = d[6]
    z.s = d[7]
    return z
}

func (z *RawMessageHeader) deserializeV2(s string) *RawMessageHeader {
    var err error
    smh := make([]byte, 0)
    if len(s) < ShortMessageHeaderLengthB64V2 {
        fmt.Println("message too short")
        return nil
    }
    if len(s) >= MessageHeaderLengthB64V2 {
        smh, err = base64.StdEncoding.DecodeString(s[:MessageHeaderLengthB64V2])
    } else {
        smh, err = base64.StdEncoding.DecodeString(s[:ShortMessageHeaderLengthB64V2])
    }
    if err != nil {
        fmt.Println("base64 conversion failed")
        return nil
    }
    return z.importBinaryHeaderV2(smh[:])
}

func (z *RawMessageHeader) importBinaryHeaderV2(smh []byte) *RawMessageHeader {
    if len(smh) < ShortMessageHeaderLengthV2 {
        return nil
    }
    if bytes.Compare(smh[:4],[]byte("M\x02\x00\x00")) != 0 {
        fmt.Println("v0200 version string mismatch")
        return nil
    }
    z.version = "0200"
    z.time = binary.BigEndian.Uint32(smh[4:8])
    z.expire = binary.BigEndian.Uint32(smh[8:12])
    //z.I = string(smh[12:45])
    //z.J = string(smh[45:78])
    //z.K = string(smh[78:111])
    z.I = hex.EncodeToString(smh[12:45])
    z.J = hex.EncodeToString(smh[45:78])
    z.K = hex.EncodeToString(smh[78:111])
    z.blocklen = binary.BigEndian.Uint32(smh[111:115])
    z.reserved = binary.BigEndian.Uint64(smh[115:123])
    if len(smh) >= MessageHeaderLengthV2 {
        var ui8 uint8
        var ui32 uint32
        z.r = string(smh[123:155])
        z.s = string(smh[155:187])
        bufnonce := bytes.NewBuffer(smh[187:188])
        binary.Read(bufnonce, binary.BigEndian, &ui8)
        bufnonce = bytes.NewBuffer(smh[188:192])
        binary.Read(bufnonce, binary.BigEndian, &ui32)
        z.nonce = ((uint64)(ui8) << 32)
        z.nonce += (uint64)(ui32)
    }
    return z
}

func (z *RawMessageHeader) Deserialize(s string) *RawMessageHeader {
    if strings.Compare(s[:3],"M01") == 0 {
        return z.deserializeV1(s)
    } else {
        return z.deserializeV2(s)
    }
}

func (z *RawMessageHeader) serializeV1() *SerializedMessageHeaderV1 {
    smh := new(SerializedMessageHeaderV1)
    s := fmt.Sprintf("M%s:%08X:%08X:%s:%s:%s:%s:%s", z.version, z.time, z.expire, z.I, z.J, z.K, z.r, z.s)
    //fmt.Println("serialized as : " + s)
    if len(s) != MessageHeaderLengthV1 {
        fmt.Printf("Message length invalid: %d chars\n", len(s))
        return nil
    }
    copy(smh[:], s)
    return smh
}

func (z *RawMessageHeader) exportBinaryHeaderV2() *BinaryMessageHeaderV2 {
    buf := new(bytes.Buffer)
    buf.WriteString("M\x02\x00\x00")
    binary.Write(buf, binary.BigEndian, z.time)
    binary.Write(buf, binary.BigEndian, z.expire)
    //buf.WriteString(z.I)
    //buf.WriteString(z.J)
    //buf.WriteString(z.K)
    I, err := hex.DecodeString(z.I)
    if err != nil {
        return nil
    }
    J, err := hex.DecodeString(z.J)
    if err != nil {
        return nil
    }
    K, err := hex.DecodeString(z.K)
    if err != nil {
        return nil
    }
    buf.WriteString(string(I))
    buf.WriteString(string(J))
    buf.WriteString(string(K))
    binary.Write(buf, binary.BigEndian, z.blocklen)
    binary.Write(buf, binary.BigEndian, z.reserved)
    buf.WriteString(z.r)
    buf.WriteString(z.s)
    binary.Write(buf, binary.BigEndian, uint8(z.nonce >> 32))
    binary.Write(buf, binary.BigEndian, uint32(z.nonce & 0xFFFFFFFF))
    //fmt.Println("serialized as : " + hex.EncodeToString(buf.Bytes()))
    if buf.Len() != MessageHeaderLengthV2 {
        //fmt.Printf("Message length invalid: %d chars\n", buf.Len())
        return nil
    }
    bmh := new(BinaryMessageHeaderV2)
    copy(bmh[:], buf.Bytes()[:])
    return bmh
}

func (z *RawMessageHeader) serializeV2() *SerializedMessageHeaderV2 {
    bmh := z.exportBinaryHeaderV2()
    b64 := make([]byte, MessageHeaderLengthB64V2)
    base64.StdEncoding.Encode(b64, bmh[:])
    //fmt.Println("as b64 " + string(b64))
    smh := new(SerializedMessageHeaderV2)
    copy(smh[:], b64)
    return smh
}

func (z *RawMessageHeader) Serialize() string {
    if strings.Compare(z.version,"0100") == 0 {
        return string(z.serializeV1()[:])
    } else {
        return string(z.serializeV2()[:])
    }
}

func (z *RawMessageHeader) SerializeV1() *SerializedMessageHeaderV1 {
    if strings.Compare(z.version,"0100") == 0 {
        return z.serializeV1()
    } else {
        return nil
    }
}

func (z *RawMessageHeader) SerializeV2() *SerializedMessageHeaderV2 {
    if strings.Compare(z.version,"0100") == 0 {
        return nil
    } else {
        return z.serializeV2()
    }
}

func (z *RawMessageHeader) ExportBinaryHeaderV2() *BinaryMessageHeaderV2 {
    if strings.Compare(z.version,"0100") == 0 {
        return nil
    } else {
        return z.exportBinaryHeaderV2()
    }
}

func ImportBinaryHeaderV2(smh []byte) *RawMessageHeader {
    z := new(RawMessageHeader)
    return z.importBinaryHeaderV2(smh)
}

func (z *RawMessageHeader) MessageTime() time.Time {
    return time.Unix(int64(z.time), 0)
}

func (z *RawMessageHeader) ExpireTime() time.Time {
    return time.Unix(int64(z.expire), 0)
}

func (z *RawMessageHeader) IKey() (k []byte, err error) {
    k, err = hex.DecodeString(z.I)
    if err != nil {
        return nil, err
    }
    return k, nil
}

func (z *RawMessageHeader) Hash() []byte {
    hashval := sha256.Sum256([]byte(z.Serialize()))
    return hashval[:]
}
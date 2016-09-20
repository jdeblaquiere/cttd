// Copyright (c) 2016 The ciphrtxt developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ciphrtxt

import (
    //"encoding/hex"
    "fmt"
    "strconv"
    "strings"
)

// RawMessageHeader treats larger data objects (EC Points, big integers) as strings
// instead of parsing them to their numerical value

type RawMessageHeader struct {
    version string
    time    uint32
    expire  uint32
    I       string
    J       string
    K       string
    r       string
    s       string
}

func (z *RawMessageHeader) Deserialize(s string) *RawMessageHeader {
    var t64 uint64
    var d = strings.Split(s, ":")
    if len(d) != 8 || strings.Compare(d[0],"M0100") != 0 {
        return nil
    }
    z.version = d[0]
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

func (z *RawMessageHeader) Serialize() string {
    return fmt.Sprintf("%s:%08X:%08X:%s:%s:%s:%s:%s", z.version, z.time, z.expire, z.I, z.J, z.K, z.r, z.s)
}

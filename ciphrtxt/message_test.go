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
    "testing"
    //"math/big"
    //"math/rand"
    "net/http"
    "io"
    //"io/ioutil"
    //"encoding/base64"
    "encoding/hex"
    //"encoding/json"
    "fmt"
    "os"
    "strconv"
    //"sync"
    "time"
)

func TestMessageIngestMove (t *testing.T) {
    hc, err := OpenHeaderCache("violet.ciphrtxt.com", 7754, "testdb/violet.ciphrtxt.com")
    if err != nil {
        t.Fail()
    }
    defer hc.Close()

    // validate based on messages from the last hour
    now := time.Now().Unix()
    mh, err := hc.getHeadersSince(uint32(now-3600))
    if err != nil {
        fmt.Println("error getHeaderSince - test failed")
        t.Fail()
    }
    
    if len(mh) == 0 {
        fmt.Println("no message headers received - test failed")
        t.Fail()
    }
    
    for _, h := range mh {
        I, err := h.IKey()
        if err != nil {
            fmt.Println("whoops:", err)
            t.Fail()
        }
        res, err := http.Get("http://violet.ciphrtxt.com:7754/api/message/download/" + hex.EncodeToString(I))
        if err != nil {
            fmt.Println("whoops:", err)
            t.Fail()
        }
        tmptime := time.Now().UnixNano()
        filepath := "./receive/"+ strconv.Itoa(int(tmptime))
        fmt.Printf("receiving %s as %s\n",hex.EncodeToString(I), filepath)
        f, err := os.Create(filepath)
        if err != nil {
            fmt.Println("whoops:", err)
            t.Fail()
        } else {
            io.Copy(f, res.Body)
            f.Close()
            m := Ingest(filepath)
            if m == nil {
                fmt.Println("whoops:", err)
                t.Fail()
            } else {
                I, err := m.IKey()
                if err != nil {
                fmt.Println("whoops:", err)
                    t.Fail()
                }
                filemove := "./messages/" + hex.EncodeToString(I)
                fmt.Printf("moving to %s\n", filemove)
                err = m.Move(filemove)
                if err != nil {
                    fmt.Println("whoops:", err)
                    t.Fail()
                }
            }
        }
    }
}

// http://indigo.bounceme.net:7754/api/message/download/0233da40ddd1bd53672f310025dc5e1f07a8a8768f4efe7ed9abfa296ec7863916

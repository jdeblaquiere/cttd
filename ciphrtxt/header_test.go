// Copyright (c) 2016 The ciphrtxt developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ciphrtxt

import (
    "testing"
    //"math/big"
    "math/rand"
    "net/http"
    "io/ioutil"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "strconv"
    "sync"
    "time"
)

type THeaderListResponse struct {
    HeaderList []string `json:"header_list"`
}

func TestDeserializeSerialize (t *testing.T) {
    res, err := http.Get("http://ciphrtxt.com:7754/api/header/list/since/0")
    if err != nil {
        fmt.Println("whoops:", err)
        t.Fail()
    }
    
    body, err := ioutil.ReadAll(res.Body)
    if err != nil {
        fmt.Println("whoops:", err)
        t.Fail()
    }
    
    s := new(THeaderListResponse)
    err = json.Unmarshal(body, &s)
    if(err != nil){
        fmt.Println("whoops:", err)
        t.Fail()
    }
    
    count := int(0)
    for _, hdr := range s.HeaderList {
        h := new(RawMessageHeader)
        h.Deserialize(hdr)
        hdr_out := h.Serialize()
        hdr_bin := h.ExportBinaryHeaderV2()
        hh := ImportBinaryHeaderV2(hdr_bin[:])
        count += 1
        
        if hdr != hdr_out {
            fmt.Println("hdr mismatch!")
            fmt.Println(" in  : " + hdr)
            fmt.Println(" out : " + hdr_out)
            fmt.Println()
            t.Fail()
        }
        
        if hh.Serialize() != hdr_out {
            fmt.Println("hdr mismatch!")
            fmt.Println(" in  : " + hh.Serialize())
            fmt.Println(" out : " + hdr_out)
            fmt.Println()
            t.Fail()
        }
        
        if hdr_bin != nil {
            b64 := base64.StdEncoding.EncodeToString(hdr_bin[:])
            if hdr != hdr_out {
                fmt.Println("binary hdr mismatch!")
                fmt.Println(" bin : " + b64)
                fmt.Println(" out : " + hdr_out)
                fmt.Println()
                t.Fail()
            }
        }
    
        dbk, err := h.dbKeys()
        if(err != nil){
            fmt.Println("whoops:", err)
            t.Fail()
        }
        //fmt.Println(hdr)
        //fmt.Println("    " + hex.EncodeToString(dbk.date))
        //fmt.Println("    " + hex.EncodeToString(dbk.expire))
        //fmt.Println("    " + hex.EncodeToString(dbk.I))
        //fmt.Println()
        
        t64, err := strconv.ParseUint(hex.EncodeToString(dbk.date)[1:9], 16, 32)
        time := uint32(t64)
        if (h.time != time) || (h.I != hex.EncodeToString(dbk.date)[9:75]) {
            t.Fail()
        }
        
        t64, err = strconv.ParseUint(hex.EncodeToString(dbk.expire)[1:9], 16, 32)
        expire := uint32(t64)
        if (h.expire != expire) || (h.I != hex.EncodeToString(dbk.expire)[9:75]) {
            t.Fail()
        }
        
        if h.I != hex.EncodeToString(dbk.I) {
            t.Fail()
        }
    }
}

func TestOpenHeaderCache (t *testing.T) {
    hc1, err := OpenHeaderCache("violet.ciphrtxt.com", 7754, "testdb/violet.ciphrtxt.com")
    if err != nil {
        t.Fail()
    }
    defer hc1.Close()

    hc2, err := OpenHeaderCache("indigo.ciphrtxt.com", 7754, "testdb/indigo.ciphrtxt.com")
    if err != nil {
        t.Fail()
    }
    defer hc2.Close()
}

func TestHeaderCacheGetTime (t *testing.T) {
    hc1, err := OpenHeaderCache("violet.ciphrtxt.com", 7754, "testdb/violet.ciphrtxt.com")
    if err != nil {
        t.Fail()
    }
    defer hc1.Close()

    hctime, err := hc1.getTime()
    if err != nil {
        t.Fail()
    }
    
    now := time.Now().Unix()
    diff := int64(hctime) - now
    if diff < 0 {
        diff = 0 - diff
    }
    
    if diff > 5 {
        t.Fail()
    }
}

func TestHeaderCacheGetHeaders (t *testing.T) {
    hc1, err := OpenHeaderCache("violet.ciphrtxt.com", 7754, "testdb/violet.ciphrtxt.com")
    if err != nil {
        t.Fail()
    }
    defer hc1.Close()

    now := time.Now().Unix()
    mh, err := hc1.getHeadersSince(uint32(now-3600))
    if err != nil {
        t.Fail()
    }
    
    if len(mh) == 0 {
        t.Fail()
    }
    
    //fmt.Printf("found %d headers\n", len(mh))
    //for _, h := range mh {
    //    fmt.Println(h.Serialize())
    //}
}

func TestHeaderCacheSync (t *testing.T) {
    hc1, err := OpenHeaderCache("violet.ciphrtxt.com", 7754, "testdb/violet.ciphrtxt.com")
    if err != nil {
        t.Fail()
    }
    defer hc1.Close()

    err = hc1.Sync()
    if err != nil {
        t.Fail()
    }
    
    //fmt.Printf("found %d headers\n", len(mh))
    //for _, h := range mh {
    //    fmt.Println(h.Serialize())
    //}
}

func TestHeaderGoroutines (t *testing.T) {
    var wg sync.WaitGroup

    hc1, err := OpenHeaderCache("violet.ciphrtxt.com", 7754, "testdb/violet.ciphrtxt.com")
    if err != nil {
        t.Fail()
    }
    defer hc1.Close()

    wg.Add(10)
    for gr := 0 ; gr < 10 ; gr++ {
    
        go func(hc *HeaderCache, gr int) {
            defer wg.Done()
            fmt.Printf("in GR %d\n", gr)
            for i := 0 ; i < 20 ; i++ {
                //fmt.Printf("in GR %d i = %d\n", gr, i)
                ago := int64(rand.Intn(60*60*24*7))

                _, err := hc.FindSince(uint32(time.Now().Unix() - ago))
                if err != nil {
                    t.Fail()
                }

                //fmt.Printf("GR %d : fetched %d\n", gr, len(hdrs))
            }
            
            fmt.Printf("GR %d done\n", gr)
        }(hc1, gr)
    }
    wg.Wait()
    
    //fmt.Printf("found %d headers\n", len(mh))
    //for _, h := range mh {
    //    fmt.Println(h.Serialize())
    //}
}

func TestTimes (t *testing.T) {
    hc, err := OpenHeaderCache("violet.ciphrtxt.com", 7754, "testdb/violet.ciphrtxt.com")
    if err != nil {
        t.Fail()
    }
    defer hc.Close()

    // last hour as golang time.Time, with a 1 minute propagation time margin
    startTime := time.Now().Add(time.Duration(-61 * time.Minute))
    // messages should expire after startTime + 7 days
    expireTime := startTime.Add(time.Duration((7 * 24) * time.Hour))

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
        if h.MessageTime().Before(startTime) {
            fmt.Println("Message before Start")
            fmt.Println("Start  : " + startTime.Format("Mon Jan _2 15:04:05 2006"))
            fmt.Println("Message: " + h.MessageTime().Format("Mon Jan _2 15:04:05 2006"))
            t.Fail()
        }
        if h.ExpireTime().Before(expireTime) {
            fmt.Println("Expire before + 7d")
            fmt.Println("Expire : " + expireTime.Format("Mon Jan _2 15:04:05 2006"))
            fmt.Println("Now + 7: " + h.ExpireTime().Format("Mon Jan _2 15:04:05 2006"))
            t.Fail()
        }
    }
    
}

func TestFindByI (t *testing.T) {
    hc, err := OpenHeaderCache("violet.ciphrtxt.com", 7754, "testdb/violet.ciphrtxt.com")
    if err != nil {
        t.Fail()
    }
    defer hc.Close()

    res, err := http.Get("http://ciphrtxt.com:7754/api/header/list/since/0")
    if err != nil {
        fmt.Println("whoops:", err)
        t.Fail()
    }
    
    body, err := ioutil.ReadAll(res.Body)
    if err != nil {
        fmt.Println("whoops:", err)
        t.Fail()
    }
    
    s := new(THeaderListResponse)
    err = json.Unmarshal(body, &s)
    if(err != nil){
        fmt.Println("whoops:", err)
        t.Fail()
    }
    
    for _, hdr := range s.HeaderList {
        h := new(RawMessageHeader)
        h.Deserialize(hdr)
        Ibin, err := h.IKey()
        if err != nil {
            t.Fail()
        }
        
        msg, err := hc.FindByI(Ibin)
        if err != nil {
            if uint32(time.Now().Unix()) < h.expire {
                fmt.Println("Error: could not find message:", h.I)
                t.Fail()
            }
        } else if msg.Serialize() != h.Serialize() {
            fmt.Println("Error: message mismatch:", h.I)
            t.Fail()
        }
    }
}

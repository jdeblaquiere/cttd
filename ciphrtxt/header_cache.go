// Copyright (c) 2016 The ciphrtxt developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ciphrtxt

import (
    "net/http"
    "io/ioutil"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "errors"
    "github.com/syndtr/goleveldb/leveldb"
)

const api_status string = "api/status/"
const api_time string = "api/time/"
const api_headers_since string = "api/header/list/since/"

// {"pubkey": "030b5a7b432ec22920e20063cb16eb70dcb62dfef28d15eb19c1efeec35400b34b", "storage": {"max_file_size": 268435456, "capacity": 137438953472, "messages": 6252, "used": 17828492}}

type StatusStorageResponse struct {
    Messages int `json:"messages"`
    Maxfilesize int `json:"max_file_size"`
    Capacity int `json:"capacity"`
    Used int `json:"used"`
}

type StatusResponse struct {
    Pubkey string `json:"pubkey"`
    Status StatusStorageResponse `json:"storage"`
}

type TimeResponse struct {
    time uint32 `json:"time"`
}

type HeaderListResponse struct {
    headers []string `json:"header_list"`
}

type HeaderCache struct {
    baseurl string
    db *leveldb.DB
    status StatusResponse
    servertime uint32
}

// NOTE : if dbpath is empty ("") header cache will be in-memory only

func OpenHeaderCache(host string, port int, dbpath string) (hc *HeaderCache, err error) {
    hc = new(HeaderCache)
    hc.baseurl = fmt.Sprintf("http://%s:%d/", host, port)
    
    res, err := http.Get(hc.baseurl + api_status)
    if err != nil {
        return nil, err
    }
    
    body, err := ioutil.ReadAll(res.Body)
    if err != nil {
        return nil, err
    }
    
    err = json.Unmarshal(body, &hc.status)
    if err != nil {
        return nil, err
    }
    
    if len(dbpath) > 0 {
        hc.db, err = leveldb.OpenFile(dbpath, nil)
        if(err != nil){
            return nil, err
        }
    } else {
        hc.db = nil
    }
    
    return hc, nil
}

func (hc *HeaderCache) Close() {
    if hc.db != nil {
        hc.db.Close()
    }
}

type dbkeys struct {
    date []byte
    expire []byte
    I []byte
}

func (h *RawMessageHeader) DBKeys() (dbk *dbkeys, err error) {
    dbk = new(dbkeys)
    dbk.date, err = hex.DecodeString(fmt.Sprintf("D%08X%s0", h.time, h.I))
    if err != nil {
        return nil, err
    }
    dbk.expire, err = hex.DecodeString(fmt.Sprintf("E%08X%s0", h.expire, h.I))
    if err != nil {
        return nil, err
    }
    dbk.I, err = hex.DecodeString(h.I)
    if err != nil {
        return nil, err
    }
    return dbk, err
}

func (hc *HeaderCache) Insert(h *RawMessageHeader) (err error) {
    if hc.db == nil {
        
    }
    dbk, err := h.DBKeys()
    if err != nil {
        return err
    }
    value := []byte(h.Serialize())
    batch := new(leveldb.Batch)
    batch.Put(dbk.date, value)
    batch.Put(dbk.expire, value)
    batch.Put(dbk.I, value)
    return hc.db.Write(batch, nil)
}

func (hc *HeaderCache) Remove(h *RawMessageHeader) (err error) {
    dbk, err := h.DBKeys()
    if err != nil {
        return err
    }
    batch := new(leveldb.Batch)
    batch.Delete(dbk.date)
    batch.Delete(dbk.expire)
    batch.Delete(dbk.I)
    return hc.db.Write(batch, nil)
}

func (hc *HeaderCache) FindByI (I []byte) (h *RawMessageHeader, err error) {
    value, err := hc.db.Get(I, nil)
    if err != nil {
        return nil, err
    }
    h = new(RawMessageHeader)
    if h.Deserialize(string(value)) == nil {
        return nil, errors.New("retreived invalid header from database")
    }
    return h, nil
}

func (hc *HeaderCache) GetTime() (servertime uint32, err error) {
    var tr TimeResponse

    res, err := http.Get(hc.baseurl + api_status)
    if err != nil {
        return 0, err
    }
    
    body, err := ioutil.ReadAll(res.Body)
    if err != nil {
        return 0, err
    }
    
    err = json.Unmarshal(body, &tr)
    if err != nil {
        return 0, err
    }
    
    return tr.time, nil
}

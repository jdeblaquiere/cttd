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
    "github.com/syndtr/goleveldb/leveldb/util"
    "strconv"
    "time"
)

const apiStatus string = "api/status/"
const apiTime string = "api/time/"
const apiHeadersSince string = "api/header/list/since/"

const refreshMinDelay = 10

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
    Time int `json:"time"`
}

type HeaderListResponse struct {
    Headers []string `json:"header_list"`
}

type HeaderCache struct {
    baseurl string
    db *leveldb.DB
    status StatusResponse
    serverTime uint32
    lastRefresh uint32
    Count int
}

// NOTE : if dbpath is empty ("") header cache will be in-memory only

func OpenHeaderCache(host string, port int, dbpath string) (hc *HeaderCache, err error) {
    hc = new(HeaderCache)
    hc.baseurl = fmt.Sprintf("http://%s:%d/", host, port)
    
    res, err := http.Get(hc.baseurl + apiStatus)
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
    
    if len(dbpath) == 0 {
        return nil, errors.New("refusing to open empty db path")
    }
    
    hc.db, err = leveldb.OpenFile(dbpath, nil)
    if err != nil {
        return nil, err
    }
    
    emptyMessage := "000000000000000000000000000000000000000000000000000000000000000000"
    expiredBegin, err := hex.DecodeString("E" + "00000000" + emptyMessage + "0")
    if err != nil {
        return nil, err
    }
    expiredEnd, err := hex.DecodeString("E" + "FFFFFFFF" + emptyMessage + "0")
    if err != nil {
        return nil, err
    }
    
    iter := hc.db.NewIterator(&util.Range{Start: expiredBegin,Limit: expiredEnd}, nil)

    count := int(0)
        
    for iter.Next() {
        count += 1
    }
    iter.Release()

    hc.Count = count
    fmt.Printf("open, found %d message headers\n", count)
    return hc, nil
}

func (hc *HeaderCache) Close() {
    if hc.db != nil {
        hc.db.Close()
        hc.db = nil
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

func (hc *HeaderCache) Insert(h *RawMessageHeader) (insert bool, err error) {
    dbk, err := h.DBKeys()
    if err != nil {
        return false, err
    }
    _, err = hc.db.Get(dbk.I, nil)
    if err == nil {
        return false, nil
    }
    value := []byte(h.Serialize())
    batch := new(leveldb.Batch)
    batch.Put(dbk.date, value)
    batch.Put(dbk.expire, value)
    batch.Put(dbk.I, value)
    err = hc.db.Write(batch, nil)
    if err != nil {
        return false, err
    }
    return true, nil
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

func (hc *HeaderCache) getTime() (serverTime uint32, err error) {
    var tr TimeResponse

    res, err := http.Get(hc.baseurl + apiTime)
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
    
    hc.serverTime = uint32(tr.Time)
    return hc.serverTime, nil
}

func (hc *HeaderCache) getHeadersSince(since uint32) (mh []RawMessageHeader, err error) {
    res, err := http.Get(hc.baseurl + apiHeadersSince + strconv.FormatInt(int64(since),10))
    if err != nil {
        return nil, err
    }
    
    body, err := ioutil.ReadAll(res.Body)
    if err != nil {
        return nil, err
    }
    
    s := new(HeaderListResponse)
    err = json.Unmarshal(body, &s)
    if err != nil {
        return nil, err
    }
    
    mh = make([]RawMessageHeader, 0)
    for _, hdr := range s.Headers {
        h := new(RawMessageHeader)
        if h.Deserialize(hdr) == nil {
            return nil, errors.New("error parsing message")
        }
        mh = append(mh, *h)
    }
    return mh, nil
}

func (hc *HeaderCache) pruneExpired() (err error) {
    emptyMessage := "000000000000000000000000000000000000000000000000000000000000000000"
    expiredBegin, err := hex.DecodeString("E" + "00000000" + emptyMessage + "0")
    if err != nil {
        return err
    }
    now := strconv.FormatUint(uint64(time.Now().Unix()),16)
    expiredEnd, err := hex.DecodeString("E" + now + emptyMessage + "0")
    if err != nil {
        return err
    }

    iter := hc.db.NewIterator(&util.Range{Start: expiredBegin,Limit: expiredEnd}, nil)
    batch := new(leveldb.Batch)
    hdr := new(RawMessageHeader)
    
    delCount := int(0)
        
    for iter.Next() {
        if hdr.Deserialize(string(iter.Value())) == nil {
            return errors.New("unable to parse database value")
        }
        dbk, err := hdr.DBKeys()
        if err != nil {
            return err
        }
        batch.Delete(dbk.date)
        batch.Delete(dbk.expire)
        batch.Delete(dbk.I)
        delCount += 1
    }
    iter.Release()
    
    err = hc.db.Write(batch, nil)
    if err == nil {
        hc.Count -= delCount
        fmt.Printf("dropping %d message headers\n", delCount)
    }
    
    return err
}

func (hc *HeaderCache) Sync() (err error) {
    now := uint32(time.Now().Unix())
    
    if (now - hc.lastRefresh) < refreshMinDelay {
        return nil
    }
    
    serverTime, err := hc.getTime()
    if err != nil {
        return err
    }
    
    err = hc.pruneExpired()
    if err != nil {
        return err
    }
    
    mhdrs, err := hc.getHeadersSince(hc.lastRefresh)
    if err != nil {
        return err
    }
    
    insCount := int(0)
        
    for _, mh := range mhdrs {
        insert, err := hc.Insert(&mh)
        if err != nil {
            return err
        }
        if insert {
            insCount += 1
        }
    }
    
    hc.serverTime = serverTime
    
    hc.Count += insCount
    fmt.Printf("insert %d message headers\n", insCount)
    
    return nil
}
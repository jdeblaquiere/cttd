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
    //"net/http"
    //"io"
    "io/ioutil"
    "encoding/hex"
    //"encoding/json"
    "fmt"
    "errors"
    "github.com/syndtr/goleveldb/leveldb"
    "github.com/syndtr/goleveldb/leveldb/util"
    "math/rand"
    "os"
    "strconv"
    "sync"
    "time"
)

const syncMaxGoroutines = 16

// ShardSector defines a sector of coverage from the message space by representing
// that message space as a circle with 512 potential buckets based on the sign
// bit and the 8 most-significant bits of the I point value in compressed form. 
// Start values span from 0x200 to 0x3FF. The number of buckets stored is 
// 512 >> ring where ring is a value in (0 .. 9). Ring 0 would capture the
// full 512 bins and ring 9 stores would only capture 1 bin. 

type ShardSector struct {
    start   int
    ring    uint
}


func (s *ShardSector) Contains(I string) (c bool, err error) {
    ringsz := 512 >> s.ring
    end := s.start + ringsz
    
    i64, err := strconv.ParseUint(I[:4], 16, 64)
    if err != nil {
        return false, err
    }
    i := int(i64)
    if end > 0x400 {
        if (i < s.start) && (i >= (end - 0x200)) {
            return false, nil
        }
    } else {
        if (i < s.start) || (i >= end) {
            return false, nil
        }
    }
    return true, nil
}

type MessageStore struct {
    rootpath string
    db *leveldb.DB
    syncMutex sync.Mutex
    Count int
    sector ShardSector
    lastRefresh uint32
    syncwg sync.WaitGroup
    iqueue chan []byte
    quitchan []chan int
    lhc *LocalHeaderCache
}

func CheckOrCreateDirectory (filepath string) (err error) {
    finfo, err := os.Stat(filepath)
    if os.IsNotExist(err) {
        return os.Mkdir(filepath, os.FileMode(0755))
    }
    
    if !finfo.IsDir() {
        return fmt.Errorf("Expected Directory, got file for %s", filepath)
    }
    
    return nil
}

func OpenMessageStore(filepath string, lhc *LocalHeaderCache, startbin int) (ms *MessageStore, err error) {
    err = CheckOrCreateDirectory(filepath)
    if err != nil {
        return nil, err
    }
    
    err = CheckOrCreateDirectory(filepath + "/store")
    if err != nil {
        return nil, err
    }
    
    ms = new(MessageStore)
    ms.rootpath = filepath
    ms.sector.start = startbin
    ms.sector.ring = 9
    ms.lhc = lhc
    
    ms.iqueue = make(chan []byte, (5*syncMaxGoroutines))
    ms.quitchan = make([]chan int, syncMaxGoroutines)
    
    ms.syncwg.Add(syncMaxGoroutines)
    for gr := 0 ; gr < syncMaxGoroutines ; gr++ {
        ms.quitchan[gr] = make(chan int)
        go func(ms *MessageStore, Iqueue chan []byte, cquit chan int, gr int) {
            defer ms.syncwg.Done()
            fmt.Printf("in GR %d\n", gr)
            for {
                var failed bool = true
                
                select {
                case I := <- Iqueue:
                    //mt.Printf("GR%d: seeking %s\n",gr,hex.EncodeToString(I))
                    ordinal := rand.Perm(len(ms.lhc.Peers))
                    for i := 0; i < len(ms.lhc.Peers); i++ {
                        phc := ms.lhc.Peers[ordinal[i]].hc
                        h, _ := phc.FindByI(I)
                        if h == nil {
                            continue
                        }
                        tmptime := time.Now().UnixNano()
                        recvpath := "./receive/"+ strconv.Itoa(int(tmptime))
                        //fmt.Printf("GR%d: pulling %s from %s as %s\n",gr,hex.EncodeToString(I), phc.baseurl, recvpath)
                        m, err := phc.tryDownloadMessage(I, recvpath)
                        if err != nil {
                            fmt.Printf("GR%d: download error can't fetch %s from %s Error\n", gr, hex.EncodeToString(I), phc.baseurl, err)
                            continue
                        }
                        Ihex := hex.EncodeToString(I)
                        filemove := "./messages/store/" + Ihex[:4] + "/" + Ihex
                        err = m.Move(filemove)
                        if err != nil {
                            continue
                        }
                        _, err = ms.Insert(m)
                        if err != nil {
                            continue
                        }
                        failed = false
                        break
                    }
                    if failed {
                        fmt.Printf("GR%d: pushing I (%s) back onto queue\n", gr, hex.EncodeToString(I))
                        // push back on the queue
                        Iqueue <- I
                    }
                case <- cquit:
                    fmt.Printf("GR %d done\n", gr)
                    return
                }
            }
        }(ms, ms.iqueue, ms.quitchan[gr], gr)
    }
    
    ms.db, err = leveldb.OpenFile(filepath + "/msgdb", nil)
    if err != nil {
        return nil, err
    }
    
    for i := 0x200; i < 0x400; i++ {
        p := fmt.Sprintf("%s/store/%04x", filepath, i)
        err = CheckOrCreateDirectory(p)
        if err != nil {
            return nil, err
        }
        
        files, err := ioutil.ReadDir(p)
        if err != nil {
            return nil, err
        }
        
        for _, f := range files {
            //fmt.Printf("Found file %s in %s\n", f.Name(), p)
            dbkey, err := hex.DecodeString(f.Name())
            if err != nil {
                fmt.Printf("Error parsing %s as hex\n", f.Name())
                continue
            }
            _, err = ms.db.Get(dbkey, nil)
            if err != nil {
                fmt.Printf("%s not found in db, inserting\n", f.Name())
                fpath := p + "/" + f.Name()
                ins, err := ms.InsertFile(fpath)
                if err != nil {
                    fmt.Printf("Failed to insert message %s\n", fpath)
                    continue
                }
                if ins {
                    fmt.Printf("inserted %s into db\n", f.Name())
                }
            }
        }
    }
    
    err = ms.recount()
    if err != nil {
        return nil, err
    }
    
    fmt.Printf("MessageStore open, found %d messages\n", ms.Count)
    return ms, nil
}

func (ms *MessageStore) Close() {
    fmt.Printf("MessageStore:Close : sending close to all goroutines\n")
    //send quit to all workers
    for _, c := range ms.quitchan {
        c <- 0
    }
    fmt.Printf("MessageStore:Close : close sent to all goroutines, waiting\n")
    ms.syncwg.Wait()
    fmt.Printf("MessageStore:Close : all goroutines completed\n")
    if ms.db != nil {
        ms.db.Close()
        ms.db = nil
    }
}

func (ms *MessageStore) recount() (err error) {
    emptyMessage := "000000000000000000000000000000000000000000000000000000000000000000"
    expiredBegin, err := hex.DecodeString("E" + "00000000" + emptyMessage + "0")
    if err != nil {
        return err
    }
    expiredEnd, err := hex.DecodeString("E" + "FFFFFFFF" + emptyMessage + "0")
    if err != nil {
        return err
    }
    
    iter := ms.db.NewIterator(&util.Range{Start: expiredBegin,Limit: expiredEnd}, nil)

    count := int(0)
        
    for iter.Next() {
        count += 1
    }
    iter.Release()

    ms.Count = count
    
    return nil
}

func (ms *MessageStore) InsertFile(filepath string) (insert bool, err error) {
    m := Ingest(filepath)
    if m == nil {
        return false, fmt.Errorf("Ingest failed for %s\n", filepath)
    }
    return ms.Insert(m)
}

func (ms *MessageStore) Insert(m *MessageFile) (insert bool, err error) {
    dbk, err := m.RawMessageHeader.dbKeys(m.Servertime)
    if err != nil {
        return false, err
    }
    _, err = ms.db.Get(dbk.I, nil)
    if err == nil {
        return false, nil
    }
    value := []byte(m.Serialize())
    batch := new(leveldb.Batch)
    batch.Put(dbk.servertime, value)
    batch.Put(dbk.expire, value)
    batch.Put(dbk.I, value)
    err = ms.db.Write(batch, nil)
    if err != nil {
        return false, err
    }
    return true, nil
}

func (ms *MessageStore) Remove(m *MessageFile) (err error) {
    dbk, err := m.RawMessageHeader.dbKeys(m.Servertime)
    if err != nil {
        return err
    }
    batch := new(leveldb.Batch)
    batch.Delete(dbk.servertime)
    batch.Delete(dbk.expire)
    batch.Delete(dbk.I)
    err = ms.db.Write(batch, nil)
    if err == nil {
        return os.Remove(m.Filepath)
    }
    return err
}

func (ms *MessageStore) pruneExpired() (err error) {
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

    iter := ms.db.NewIterator(&util.Range{Start: expiredBegin,Limit: expiredEnd}, nil)
    batch := new(leveldb.Batch)
    m := new(MessageFile)
    
    delCount := int(0)
        
    for iter.Next() {
        if m.Deserialize(iter.Value()) == nil {
            return errors.New("unable to parse database value")
        }
        dbk, err := m.RawMessageHeader.dbKeys(m.Servertime)
        if err != nil {
            return err
        }
        batch.Delete(dbk.expire)
        batch.Delete(dbk.I)
        delCount += 1
    }
    iter.Release()
    
    err = ms.db.Write(batch, nil)
    if err == nil {
        ms.Count -= delCount
        fmt.Printf("MessageStore: dropping %d messages\n", delCount)
    }
    
    return err
}

func (ms *MessageStore) FindByI (I []byte) (m *MessageFile, err error) {
    //ms.Sync()

    value, err := ms.db.Get(I, nil)
    if err != nil {
        return nil, err
    }
    m = new(MessageFile)
    if m.Deserialize(value) == nil {
        return nil, errors.New("retreived invalid message from database")
    }
    return m, nil
}

func (ms *MessageStore) syncSector(sector ShardSector) (err error) {
    lhc := ms.lhc
    lhc.Sync()
    
    fmt.Printf("MessageStore.syncSector : refresh %04x-%d\n", sector.start, sector.ring)
    
    segHeaders, err := lhc.findSector(sector)
    if err != nil {
        return err
    }
    
    fmt.Printf("MessageStore.syncSector: %d headers in scope\n", len(segHeaders))
    
    for _, s := range segHeaders {
        if s.version == "0100" {
            continue
        }
        I, err := hex.DecodeString(s.I)
        if err != nil {
            return err
        }
        _, err = ms.FindByI(I)
        if err != nil {
            //fmt.Printf("MessageStore.syncSector : queueing %s\n", s.I)
            ms.iqueue <- I
        }
    }
    
    return nil
}

func (ms *MessageStore) refreshSector(sector ShardSector, since uint32) (err error) {
    lhc := ms.lhc
    lhc.Sync()
    
    fmt.Printf("MessageStore.refreshSector : refresh %04x-%d\n", sector.start, sector.ring)
    
    segHeaders, err := lhc.FindSince(since)
    if err != nil {
        return err
    }
    
    fmt.Printf("")
    
    for _, s := range segHeaders {
        if s.version == "0100" {
            continue
        }
        c, err := sector.Contains(s.I)
        if err != nil {
            return err
        }
        if c {
            I, err := hex.DecodeString(s.I)
            if err != nil {
                return err
            }
            _, err = ms.FindByI(I)
            if err != nil {
                //fmt.Printf("MessageStore.refreshSector : queueing %s\n", s.I)
                ms.iqueue <- I
            }
        }
    }
    
    return nil
}

func (ms *MessageStore) populate(ring uint) (err error) {
    newSync := ms.lhc.lastRefresh
    lastSync := ms.lhc.lastRefresh
    currentRing := ms.sector.ring
    target := ms.sector
    
    // validate that the current sector is covered
    
    ms.syncSector(ms.sector)
    
    // step "down" one ring at a time: add "next" sector; refresh new for combined
    
    for r := currentRing; r > ring; r-- {
        extent := 512 >> r
        target = ShardSector{
            start: ((ms.sector.start + extent) & 0x01ff) | 0x0200,
            ring: r,
        }
    
        ms.syncSector(target)
        
        target = ShardSector{
            start: ms.sector.start,
            ring: r - 1,
        }
        
        newSync = ms.lhc.lastRefresh
        ms.refreshSector(target, lastSync)
        lastSync = newSync
    }
    
    ms.sector = target
    ms.lastRefresh = lastSync
    
    return nil
}

func (ms *MessageStore) Sync() (err error) {
    lhc := ms.lhc
    
    lhc.Sync()
    
    newSync := lhc.lastRefresh
    
    ms.refreshSector(ms.sector, ms.lastRefresh)
    
    ms.lastRefresh = newSync
    
    return nil
}

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
    "io/ioutil"
    "encoding/hex"
    //"encoding/json"
    "fmt"
    "errors"
    "github.com/syndtr/goleveldb/leveldb"
    "github.com/syndtr/goleveldb/leveldb/util"
    "os"
    "strconv"
    "sync"
    "time"
)

type MessageStore struct {
    rootpath string
    db *leveldb.DB
    syncMutex sync.Mutex
    Count int
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

func OpenMessageStore(filepath string) (ms *MessageStore, err error) {
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
                return nil, err
            }   
            _, err = ms.db.Get(dbkey, nil)
            if err != nil {
                fmt.Printf("%s not found in db, inserting\n", f.Name())
                fpath := p + "/" + f.Name()
                ins, err := ms.InsertFile(fpath)
                if err != nil {
                    fmt.Printf("Failed to insert message\n", fpath)
                    return nil, err
                }
                if ins {
                    fmt.Printf("inserted %s into db\n", f.Name())
                }
            }
        }
    }
    
    return ms, nil
}

func (ms *MessageStore) InsertFile(filepath string) (insert bool, err error) {
    m := Ingest(filepath)
    if m == nil {
        return false, fmt.Errorf("Ingest failed for %s\n", filepath)
    }
    return ms.Insert(m)
}

func (ms *MessageStore) Insert(m *MessageFile) (insert bool, err error) {
    dbk, err := m.RawMessageHeader.dbKeys()
    if err != nil {
        return false, err
    }
    _, err = ms.db.Get(dbk.I, nil)
    if err == nil {
        return false, nil
    }
    value := []byte(m.Serialize())
    batch := new(leveldb.Batch)
    batch.Put(dbk.expire, value)
    batch.Put(dbk.I, value)
    err = ms.db.Write(batch, nil)
    if err != nil {
        return false, err
    }
    return true, nil
}

func (ms *MessageStore) Remove(m *MessageFile) (err error) {
    dbk, err := m.RawMessageHeader.dbKeys()
    if err != nil {
        return err
    }
    batch := new(leveldb.Batch)
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
        dbk, err := m.RawMessageHeader.dbKeys()
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
        fmt.Printf("dropping %d message headers\n", delCount)
    }
    
    return err
}


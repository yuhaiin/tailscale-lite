package tailscalelite

import (
 "crypto/rand"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"

 "tailscale.com/types/key"
 "tailscale.com/types/persist"
)

// diskState is private state, including secrets. Never log or expose it.
type diskState struct {
 MachineKey key.MachinePrivate `json:"machine_key"`
 Persist persist.Persist `json:"persist"`
}

func readState(path string)(diskState,error){
 var s diskState
 fi,err:=os.Lstat(path)
 if errors.Is(err,os.ErrNotExist){return s,nil}
 if err!=nil{return s,fmt.Errorf("stat identity: %w",err)}
 if !fi.Mode().IsRegular() || fi.Mode().Perm()&0077!=0 {
  return s,errors.New("tailscale-lite: state must be a private regular file (0600)")
 }
 b,err:=os.ReadFile(path)
 if err!=nil{return s,fmt.Errorf("read identity: %w",err)}
 if err:=json.Unmarshal(b,&s);err!=nil{return s,fmt.Errorf("parse identity: %w",err)}
 return s,nil
}

func writeState(path string,s diskState)error {
 dir:=filepath.Dir(path)
 if err:=os.MkdirAll(dir,0700);err!=nil{return err}
 b,err:=json.MarshalIndent(s,"","  ")
 if err!=nil{return err}
 f,err:=os.CreateTemp(dir,".tailscale-lite-*")
 if err!=nil{return err}
 name:=f.Name()
 defer os.Remove(name)
 if err=f.Chmod(0600);err!=nil{f.Close();return err}
 if _,err=io.Copy(f,bytesReader(b));err!=nil{f.Close();return err}
 if err=f.Sync();err!=nil{f.Close();return err}
 if err=f.Close();err!=nil{return err}
 if err=os.Rename(name,path);err!=nil{return err}
 // The identity must be durable even across abrupt host shutdown.
 if d,err:=os.Open(dir);err==nil{_ =d.Sync();_ =d.Close()}
 return nil
}

// Keep state writer dependency-light.
type byteReader struct{b []byte; pos int}
func(r *byteReader)Read(p []byte)(int,error){
 if r.pos==len(r.b){return 0,io.EOF}
 n:=copy(p,r.b[r.pos:]);r.pos+=n;return n,nil
}
func bytesReader(b []byte)io.Reader{return &byteReader{b:b}}
var _ = rand.Reader

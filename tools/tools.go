package tools

import (
	"crypto/md5"
	"crypto/sha1"
	"fmt"
	"os/exec"
	"runtime"
	"sync/atomic"
	"time"
)

var Mid string = "00"
var ono_seq uint32 = 0
var NewOno = func() string {
	seq := atomic.AddUint32(&ono_seq, 1)
	seq = seq % 100000000
	return fmt.Sprintf("%v%v%08d", time.Now().Format("20060102150405"), Mid, seq)
}

func Exec(cmds string) (string, error) {
	var bys []byte
	var err error
	switch runtime.GOOS {
	case "windows":
		bys, err = exec.Command("cmd", "/C", cmds).Output()
	default:
		bys, err = exec.Command("bash", "-c", cmds).Output()
	}
	return string(bys), err
}

func SHA1(bys []byte) string {
	h := sha1.New()
	h.Write(bys)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func MD5(bys []byte) string {
	h := md5.New()
	h.Write(bys)
	return fmt.Sprintf("%x", h.Sum(nil))
}

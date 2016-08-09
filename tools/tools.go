package tools

import (
	"fmt"
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

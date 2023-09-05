package weixin

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/Centny/tps/tools"
	log "github.com/sirupsen/logrus"
)

type Conf struct {
	Appid          string
	Mchid          string
	AppSecret      string
	PaySecret      string
	MessageURL     string
	MpAppid        string
	ManualUsername string
	ManualPassword string
	ApiClient      *http.Client
}

func (c *Conf) Md5Sign(data string) string {
	return strings.ToUpper(tools.MD5([]byte(data + "&key=" + c.PaySecret)))
}

func (c *Conf) Md5SignV(o interface{}) string {
	var args = url.Values{}
	switch o.(type) {
	case AnyArgs:
		for key, val := range o.(AnyArgs) {
			if key == "sign" {
				continue
			}
			if len(val) < 1 {
				continue
			}
			args.Add(key, val)
		}
	default:
		var o_val = reflect.ValueOf(o).Elem()
		var o_typ = reflect.TypeOf(o).Elem()
		var fields_l = o_typ.NumField()
		for i := 0; i < fields_l; i++ {
			var field = o_typ.Field(i)
			var key = field.Tag.Get("xml")
			key = strings.Split(key, ",")[0]
			if key == "sign" || key == "xml" {
				continue
			}
			var val = fmt.Sprintf("%v", o_val.Field(i))
			if len(val) < 1 {
				continue
			}
			args.Add(key, fmt.Sprintf("%v", o_val.Field(i)))
		}
	}
	var data = args.Encode()
	data, _ = url.QueryUnescape(data)
	return c.Md5Sign(data)
}

func (c *Conf) Md5Verify(data, sign string) error {
	if c.Md5Sign(data) == sign {
		return nil
	} else {
		return fmt.Errorf("md5 verify fail")
	}
}

var ShowLog = false

func slog(format string, args ...interface{}) {
	if ShowLog {
		log.Debugf(format, args...)
	}
}

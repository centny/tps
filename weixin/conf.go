package weixin

import (
	"fmt"
	"github.com/Centny/gwf/util"
	"net/url"
	"reflect"
	"strings"
)

type Conf struct {
	Appid     string
	Mchid     string
	Key       string
	AppSecret string
}

func (c *Conf) Load(appid, mchid, key, appsecret string) {
	c.Appid, c.Mchid, c.Key, c.AppSecret = appid, mchid, key, appsecret
}

func (c *Conf) Md5Sign(data string) string {
	return strings.ToUpper(util.Md5_b([]byte(data + "&key=" + c.Key)))
}

func (c *Conf) Md5SignV(o interface{}) string {
	var o_val = reflect.ValueOf(o).Elem()
	var o_typ = reflect.TypeOf(o).Elem()
	var fields_l = o_typ.NumField()
	var args = url.Values{}
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
	var data = args.Encode()
	data, _ = url.QueryUnescape(data)
	return c.Md5Sign(data)
}

func (c *Conf) Md5Verify(data, sign string) error {
	if c.Md5Sign(data) == sign {
		return nil
	} else {
		return util.Err("md5 verify fail")
	}
}

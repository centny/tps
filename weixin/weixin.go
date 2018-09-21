package weixin

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Centny/gwf/log"
	"github.com/Centny/gwf/routing"
	"github.com/Centny/gwf/util"
)

type Evh interface {
	OnNotify(c *Client, hs *routing.HTTPSession, nativ *NaviteNotifyArgs) error
}
type Client struct {
	UnifiedOrder string
	QueryOrder   string
	// Native       Conf
	Conf map[string]*Conf
	H    Evh
	Host string
	Pre  string
	Tmp  string
	CmdF string
}

func NewClient(unified, query, host string, h Evh) *Client {
	return &Client{
		UnifiedOrder: unified,
		QueryOrder:   query,
		H:            h,
		Host:         host,
		Tmp:          "/tmp/weixin",
		CmdF:         "/usr/local/bin/qrencode %v -o %v",
		Conf:         map[string]*Conf{},
	}
}

func (c *Client) C(key string) *Conf {
	var conf = c.Conf[key]
	if conf == nil {
		conf = &Conf{}
		c.Conf[key] = conf
	}
	return conf
}

// func (c *Client) CreateNativeOrder(notify_url, out_trade_no, body string, total_fee float64) (*OrderBack, error) {
// 	return c.CreateOrder("Native", notify_url, out_trade_no, body, total_fee)
// }

func (c *Client) CreateOrder(key, openid, notify_url, out_trade_no, body string, total_fee float64, trade string) (*OrderBack, error) {
	var args = &OrderArgs{}
	args.NotifyUrl, args.OutTradeNo = notify_url, out_trade_no
	args.Body = body
	args.TotalFee = int(total_fee * 100)
	args.TradeType = trade
	args.Openid = openid
	conf := c.Conf[key]
	if conf == nil {
		return nil, fmt.Errorf("conf not found by key(%v)", key)
	}
	return c.CreateOrderV(args, conf)
}

func (c *Client) CreateOrderQr(key, notify_url, out_trade_no, body string, total_fee float64) (qr string, back *OrderBack, err error) {
	back, err = c.CreateOrder(key, "", notify_url, out_trade_no, body, total_fee, TT_NATIVE)
	if err != nil {
		return
	}
	os.MkdirAll(c.Tmp, os.ModePerm)
	var tmpf = filepath.Join(c.Tmp, "wx_"+out_trade_no+".png")
	_, err = util.Exec2(fmt.Sprintf(c.CmdF, back.CodeUrl, tmpf))
	if err != nil {
		return
	}
	qr = fmt.Sprintf("%v%v/qr/wx_%v.png", c.Host, c.Pre, out_trade_no)
	return
}

func (c *Client) CreateAppOrder(key, notify_url, out_trade_no, body string, total_fee float64) (args *OrderAppArgs, back *OrderBack, err error) {
	var conf = c.Conf[key]
	if conf == nil {
		return nil, nil, fmt.Errorf("conf not found by key(%v)", key)
	}
	back, err = c.CreateOrder(key, "", notify_url, out_trade_no, body, total_fee, TT_APP)
	if err == nil {
		args = &OrderAppArgs{
			Appid:     conf.Appid,
			Partnerid: conf.Mchid,
			Prepayid:  back.PrepayId,
			Package:   "Sign=WXPay",
			Noncestr:  strings.ToUpper(util.UUID()),
			Timestamp: util.NowSec() / 1000,
		}
		args.SetSign(conf)
	}
	return
}

func (c *Client) CreateH5Order(key, openid, notify_url, out_trade_no, body string, total_fee float64) (args *OrderH5Args, back *OrderBack, err error) {
	var conf = c.Conf[key]
	if conf == nil {
		return nil, nil, fmt.Errorf("conf not found by key(%v)", key)
	}
	back, err = c.CreateOrder(key, openid, notify_url, out_trade_no, body, total_fee, TT_JSAPI)
	if err == nil {
		args = &OrderH5Args{
			Appid:     conf.Appid,
			SignType:  "MD5",
			Package:   "prepay_id=" + back.PrepayId,
			NonceStr:  strings.ToUpper(util.UUID()),
			TimeStamp: util.NowSec() / 1000,
		}
		args.SetSign(conf)
	}
	return
}

func (c *Client) LoadOpenID(key, code string) (res util.Map, err error) {
	var conf = c.Conf[key]
	if conf == nil {
		return nil, fmt.Errorf("conf not found by key(%v)", key)
	}
	return util.HGet2("https://api.weixin.qq.com/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code", conf.Appid, conf.AppSecret, code)
}

func (c *Client) CreateOrderV(args *OrderArgs, conf *Conf) (*OrderBack, error) {
	args.Appid, args.Mchid = conf.Appid, conf.Mchid
	args.SetSign(conf)
	var bys, err = xml.Marshal(args)
	if err != nil {
		err = util.Err("Client.CreateOrder  marshal fail with error(%v)", err)
		return nil, err
	}
	slog("Client.CreateOrder(Weixin) do create order by data:\n%v", string(bys))
	code, res, err := util.HPostN(c.UnifiedOrder, "application/xml", bytes.NewBuffer(bys))
	if err != nil {
		err = util.Err("Client.CreateOrder post wexin(%v) fail with error(%v)", c.UnifiedOrder, err)
		return nil, err
	}
	if code != 200 {
		err = util.Err("Client.CreateOrder post wexin(%v) fail with error(response code %v)", c.UnifiedOrder, code)
		return nil, err
	}
	var ores = &OrderBack{}
	err = xml.Unmarshal([]byte(res), ores)
	if err != nil {
		err = util.Err("Client.CreateOrder xml unmarshal with data(\n%v\n) fail with error(%v)", res, err)
		return nil, err
	}
	if ores.ReturnCode != "SUCCESS" {
		err = util.Err("Client.CreateOrder weixin creat order by data(\n%v\n) fail with code(%v)error(%v)->%v", string(bys), ores.ReturnCode, ores.ReturnMsg, ores)
		return nil, err
	}
	err = ores.VerifySign(conf, ores.Sign)
	if err != nil {
		err = util.Err("Client.CreateOrder verify sign with data(\n%v\n) fail with error(%v)", res, err)
		return nil, err
	}
	return ores, err
}

func (c *Client) Query(args *OrderQueryArgs, conf *Conf) (*OrderQueryBack, error) {
	args.Appid, args.Mchid = conf.Appid, conf.Mchid
	args.SetSign(conf)
	var bys, err = xml.Marshal(args)
	if err != nil {
		err = util.Err("Client.CreateOrder  marshal fail with error(%v)", err)
		return nil, err
	}
	code, res, err := util.HPostN(c.QueryOrder, "text/xml", bytes.NewBuffer(bys))
	if err != nil {
		err = util.Err("Client.CreateOrder post wexin(%v) fail with error(%v)", c.UnifiedOrder, err)
		return nil, err
	}
	if code != 200 {
		err = util.Err("Client.CreateOrder post wexin(%v) fail with error(response code %v)", c.UnifiedOrder, code)
		return nil, err
	}
	var ores = &OrderQueryBack{}
	err = xml.Unmarshal([]byte(res), ores)
	if err != nil {
		err = util.Err("Client.CreateOrder xml unmarshal with data(%v) fail with error(%v)", res, err)
		return nil, err
	}
	err = ores.VerifySign(conf, ores.Sign)
	if err != nil {
		err = util.Err("Client.CreateOrder verify sign with data(%v) fail with error(%v)", res, err)
		return nil, err
	}
	return ores, err
}

func (c *Client) Notify(hs *routing.HTTPSession) routing.HResult {
	_, key := path.Split(hs.R.URL.Path)
	var addr = hs.R.Header.Get("X-Real-IP")
	if len(addr) < 1 {
		addr = hs.R.RemoteAddr
	}
	log.D("Client.NativeNotify(Weixin) receive notify on %v from %v", key, addr)
	var res = &NaviteNotifyBack{}
	defer func() {
		bys, _ := xml.Marshal(res)
		hs.W.Write(bys)
	}()
	conf := c.Conf[key]
	if conf == nil {
		err := fmt.Errorf("conf not found by key(%v)", key)
		log.E("Client.Notify(Weixin) notify fail with error(%v)%v", err)
		res.ReturnCode = "FAIL"
		res.ReturnMsg = err.Error()
		return routing.HRES_RETURN
	}
	var anyArgs = AnyNotifyArgs{}
	var bys, err = hs.UnmarshalX_v(&anyArgs)
	if err != nil {
		log.E("Client.NativeNotify(Weixin) %v", err)
		res.ReturnCode = "FAIL"
		res.ReturnMsg = err.Error()
		return routing.HRES_RETURN
	}
	err = anyArgs.VerifySign(conf, anyArgs["sign"])
	if err != nil {
		log.E("Client.NativeNotify(Weixin) verify fail with error(%v)->\n%v", err, string(bys))
		res.ReturnCode = "FAIL"
		res.ReturnMsg = err.Error()
		return routing.HRES_RETURN
	}
	var native = &NaviteNotifyArgs{}
	err = xml.Unmarshal(bys, native)
	if err != nil {
		log.E("Client.NativeNotify(Weixin) parse xml to object fail with error(%v)->\n%v", err, string(bys))
		res.ReturnCode = "FAIL"
		res.ReturnMsg = err.Error()
		return routing.HRES_RETURN
	}
	slog("Client.NativeNotify(Weixin) receive verify notify from address(%v), the data is:\n%v", addr, string(bys))
	err = c.H.OnNotify(c, hs, native)
	if err == nil {
		res.ReturnCode = "SUCCESS"
		res.ReturnMsg = "OK"
		return routing.HRES_RETURN
	} else {
		log.E("Client.Notify(Weixin) notify fail with error(%v)->\n%v", err, string(bys))
		res.ReturnCode = "FAIL"
		res.ReturnMsg = err.Error()
		return routing.HRES_RETURN
	}
}

func (c *Client) Hand(pre string, mux *routing.SessionMux) {
	c.Pre = pre
	mux.HFunc("^"+pre+"/notify/[^/]*(\\?.*)?$", c.Notify)
	mux.Handler("^"+pre+"/qr.*$", http.StripPrefix(pre+"/qr", http.FileServer(http.Dir(c.Tmp))))
}

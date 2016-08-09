package weixin

import (
	"bytes"
	"encoding/xml"
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
	Native       Conf
	H            Evh
}

func NewClient(unified, query string, h Evh) *Client {
	return &Client{
		UnifiedOrder: unified,
		QueryOrder:   query,
		H:            h,
	}
}

func (c *Client) CreateNativeOrder(notify_url, out_trade_no, body string, total_fee float64) (*OrderBack, error) {
	var args = &OrderArgs{}
	args.NotifyUrl, args.OutTradeNo = notify_url, out_trade_no
	args.Body = body
	args.TotalFee = int(total_fee * 100)
	args.TradeType = TT_NATIVE
	return c.CreateOrder(args, &c.Native)
}

func (c *Client) CreateOrder(args *OrderArgs, conf *Conf) (*OrderBack, error) {
	args.Appid, args.Mchid = conf.Appid, conf.Mchid
	args.SetSign(conf)
	var bys, err = xml.Marshal(args)
	if err != nil {
		err = util.Err("Client.CreateOrder  marshal fail with error(%v)", err)
		return nil, err
	}
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
		err = util.Err("Client.CreateOrder weixin creat order by data(\n%v\n) fail with error(%v)", string(bys), ores.ReturnMsg)
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

func (c *Client) NativeNotify(hs *routing.HTTPSession) routing.HResult {
	var res = &NaviteNotifyBack{}
	defer func() {
		bys, _ := xml.Marshal(res)
		hs.W.Write(bys)
	}()
	var native = &NaviteNotifyArgs{}
	var bys, err = hs.UnmarshalX_v(native)
	if err != nil {
		log.E("Client.Notify %v", err)
		res.ReturnCode = "FAIL"
		res.ReturnMsg = err.Error()
		return routing.HRES_RETURN
	}
	err = native.VerifySign(&c.Native, native.Sign)
	if err != nil {
		log.E("Client.Notify verify fail with error(%v)->\n%v", err, string(bys))
		res.ReturnCode = "FAIL"
		res.ReturnMsg = err.Error()
		return routing.HRES_RETURN
	}
	err = c.H.OnNotify(c, hs, native)
	if err == nil {
		res.ReturnCode = "SUCCESS"
		res.ReturnMsg = "OK"
		return routing.HRES_RETURN
	} else {
		log.E("Client.Notify notify fail with error(%v)->\n%v", err, string(bys))
		res.ReturnCode = "FAIL"
		res.ReturnMsg = err.Error()
		return routing.HRES_RETURN
	}
}

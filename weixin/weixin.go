package weixin

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codingeasygo/util/converter"
	"github.com/codingeasygo/util/uuid"
	"github.com/codingeasygo/util/xhttp"
	"github.com/codingeasygo/util/xmap"
	"github.com/codingeasygo/web"
	"github.com/gomodule/redigo/redis"

	"github.com/Centny/rediscache"
	"github.com/Centny/tps/tools"

	log "github.com/sirupsen/logrus"
)

type Evh interface {
	OnPayNotify(c *Client, hs *web.Session, nativ *PayNotifyArgs) error
	OnRefundNotify(c *Client, hs *web.Session, nativ *RefundNotifyArgs) error
}
type Client struct {
	UnifiedOrder string
	QueryOrder   string
	RefundOrder  string
	// Native       Conf
	Conf map[string]*Conf
	H    Evh
	Host string
	Pre  string
	Tmp  string
	CmdF string

	baseAccessTokenLck sync.RWMutex
	jsapiTicketLck     sync.RWMutex
	UniformSendRunning bool
	UniformSendQueue   chan *UniformSendArgs
	AccessTokenTimeout int64
	WeixinAPIServer    string
}

func NewClient(host string, h Evh) *Client {
	return &Client{
		UnifiedOrder:       "https://api.mch.weixin.qq.com/pay/unifiedorder",
		QueryOrder:         "https://api.mch.weixin.qq.com/pay/orderquery",
		RefundOrder:        "https://api.mch.weixin.qq.com/secapi/pay/refund",
		H:                  h,
		Host:               host,
		Tmp:                "/tmp/weixin",
		CmdF:               "/usr/local/bin/qrencode %v -o %v",
		Conf:               map[string]*Conf{},
		baseAccessTokenLck: sync.RWMutex{},
		jsapiTicketLck:     sync.RWMutex{},
		UniformSendQueue:   make(chan *UniformSendArgs, 10000),
		AccessTokenTimeout: 6000 * 1000,
		WeixinAPIServer:    "https://api.weixin.qq.com",
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

func (c *Client) CreateOrder(key, openid, notify_url, out_trade_no, body string, total_fee int, trade, attach string) (AnyArgs, error) {
	var args = &OrderArgs{}
	args.NotifyURL, args.OutTradeNo = notify_url, out_trade_no
	args.Body = body
	args.TotalFee = total_fee
	args.TradeType = trade
	args.Openid = openid
	args.Attach = attach
	conf := c.Conf[key]
	if conf == nil {
		return nil, fmt.Errorf("conf not found by key(%v)", key)
	}
	return c.CreateOrderV(args, conf)
}

func (c *Client) CreateRefundOrder(key, notify_url, out_trade_no, out_refund_no string, total_fee, refund_fee int) (AnyArgs, error) {
	var args = &RefundArgs{}
	args.NotifyURL = notify_url
	args.OutTradeNo = out_trade_no
	args.OutRefundNo = out_refund_no
	args.TotalFee = total_fee
	args.RefundFee = refund_fee
	args.NonceStr = uuid.New()
	conf := c.Conf[key]
	if conf == nil {
		return nil, fmt.Errorf("conf not found by key(%v)", key)
	}
	return c.CreateRefundOrderV(args, conf)
}

func (c *Client) CreateOrderQr(key, notify_url, out_trade_no, body string, total_fee int) (qr string, back AnyArgs, err error) {
	back, err = c.CreateOrder(key, "", notify_url, out_trade_no, body, total_fee, TT_NATIVE, "")
	if err != nil {
		return
	}
	os.MkdirAll(c.Tmp, os.ModePerm)
	var tmpf = filepath.Join(c.Tmp, "wx_"+out_trade_no+".png")
	_, err = tools.Exec(fmt.Sprintf(c.CmdF, back["code_url"], tmpf))
	if err != nil {
		return
	}
	qr = fmt.Sprintf("%v%v/qr/wx_%v.png", c.Host, c.Pre, out_trade_no)
	return
}

func (c *Client) CreateAppOrder(key, notify_url, out_trade_no, body string, total_fee int) (args *OrderAppArgs, back AnyArgs, err error) {
	var conf = c.Conf[key]
	if conf == nil {
		return nil, nil, fmt.Errorf("conf not found by key(%v)", key)
	}
	back, err = c.CreateOrder(key, "", notify_url, out_trade_no, body, total_fee, TT_APP, "")
	if err == nil {
		args = &OrderAppArgs{
			Appid:     conf.Appid,
			Partnerid: conf.Mchid,
			Prepayid:  back["prepay_id"],
			Package:   "Sign=WXPay",
			Noncestr:  strings.ToUpper(uuid.New()),
			Timestamp: time.Now().Local().UnixNano() / 1e6 / 1000,
		}
		args.SetSign(conf)
	}
	return
}

func (c *Client) CreateH5Order(key, openid, notify_url, out_trade_no, body string, total_fee int, attach string) (args *OrderH5Args, back AnyArgs, err error) {
	var conf = c.Conf[key]
	if conf == nil {
		return nil, nil, fmt.Errorf("conf not found by key(%v)", key)
	}
	back, err = c.CreateOrder(key, openid, notify_url, out_trade_no, body, total_fee, TT_JSAPI, attach)
	if err == nil {
		args = &OrderH5Args{
			Appid:     conf.Appid,
			SignType:  "MD5",
			Package:   "prepay_id=" + back["prepay_id"],
			NonceStr:  strings.ToUpper(uuid.New()),
			TimeStamp: fmt.Sprintf("%v", time.Now().Local().UnixNano()/1e6/1000),
		}
		args.SetSign(conf)
	}
	return
}

func (c *Client) GenerateAuthURL(key, scope, redirect, state string) (uri string, err error) {
	var conf = c.Conf[key]
	if conf == nil {
		err = fmt.Errorf("conf not found by key(%v)", key)
		return
	}
	uri = fmt.Sprintf(
		`https://open.weixin.qq.com/connect/oauth2/authorize?appid=%v&redirect_uri=%v&response_type=code&scope=%v&state=%v#wechat_redirect`,
		conf.Appid, url.QueryEscape(redirect), scope, state,
	)
	return
}

func (c *Client) LoadJsCodeSession(key, code string) (ret *Code2SessionReturn, err error) {
	var conf = c.Conf[key]
	if conf == nil {
		err = fmt.Errorf("conf not found by key(%v)", key)
		return
	}
	var data string
	for i := 0; i < 5; i++ {
		data, err = xhttp.GetText("%v/sns/jscode2session?appid=%v&secret=%v&js_code=%v&grant_type=authorization_code", c.WeixinAPIServer, conf.Appid, conf.AppSecret, code)
		if err == nil {
			break
		}
	}
	if err != nil {
		log.Warnf("Client load jscode2session fail with %v", err)
		err = fmt.Errorf("load jscode2session")
		return
	}
	ret = &Code2SessionReturn{}
	err = json.Unmarshal([]byte(data), ret)
	return
}

func (c *Client) LoadUserAccessToken(key, code string) (ret *AccessTokenReturn, err error) {
	var conf = c.Conf[key]
	if conf == nil {
		err = fmt.Errorf("conf not found by key(%v)", key)
		return
	}
	var data string
	for i := 0; i < 5; i++ {
		data, err = xhttp.GetText("%v/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code", c.WeixinAPIServer, conf.Appid, conf.AppSecret, code)
		if err == nil {
			break
		}
	}
	if err != nil {
		log.Warnf("Client load user access token fail with %v", err)
		err = fmt.Errorf("load user access token")
		return
	}
	ret = &AccessTokenReturn{}
	err = json.Unmarshal([]byte(data), ret)
	if err != nil {
		return
	}
	if ret.Code > 0 {
		err = fmt.Errorf("errcode:%v,errmsg:%v", ret.Code, ret.Message)
	}
	return
}

func (c *Client) LoadBaseAccessToken(key string, cache bool) (ret *AccessTokenReturn, err error) {
	var conf = c.Conf[key]
	if conf == nil {
		err = fmt.Errorf("conf not found by key(%v)", key)
		return
	}
	c.baseAccessTokenLck.Lock()
	defer c.baseAccessTokenLck.Unlock()
	conn := rediscache.C()
	defer conn.Close()
	vals, err := redis.Strings(conn.Do(
		"MGET",
		fmt.Sprintf("base_token_%v_timestamp", key),
		fmt.Sprintf("base_token_%v_value", key),
	))
	if err != nil && err != redis.ErrNil {
		return
	}
	now := time.Now().Local().UnixNano() / 1e6
	ts, _ := strconv.ParseInt(vals[0], 10, 64)
	if cache && now-ts*1000 < c.AccessTokenTimeout && len(vals[1]) > 0 {
		ret = &AccessTokenReturn{
			AccessToken: vals[1],
			Code:        0,
		}
		log.Debugf("Client load base acess token from cache with %v", ret.AccessToken)
		return
	}
	var data string
	for i := 0; i < 5; i++ {
		data, err = xhttp.GetText("%v/cgi-bin/token?grant_type=client_credential&appid=%v&secret=%v", c.WeixinAPIServer, conf.Appid, conf.AppSecret)
		if err == nil {
			break
		}
	}
	if err != nil {
		log.Warnf("Client load base access token fail with %v", err)
		err = fmt.Errorf("load base access token")
		return
	}
	ret = &AccessTokenReturn{}
	err = json.Unmarshal([]byte(data), ret)
	if err != nil {
		return
	}
	if ret.Code > 0 {
		err = fmt.Errorf("errcode:%v,errmsg:%v", ret.Code, ret.Message)
		return
	}
	log.Debugf("Client require new base acess token success with %v", ret.AccessToken)
	_, err = conn.Do(
		"MSET",
		fmt.Sprintf("base_token_%v_timestamp", key), time.Now().Local().UnixNano()/1e6/1000,
		fmt.Sprintf("base_token_%v_value", key), ret.AccessToken,
	)
	return
}

func (c *Client) LoadUserinfo(key, accessToken, openid string) (ret *UserinfoBack, err error) {
	var conf = c.Conf[key]
	if conf == nil {
		err = fmt.Errorf("conf not found by key(%v)", key)
		return
	}
	var data string
	for i := 0; i < 5; i++ {
		data, err = xhttp.GetText("%v/sns/userinfo?access_token=%v&openid=%v&lang=zh_CN", c.WeixinAPIServer, accessToken, openid)
		if err == nil {
			break
		}
	}
	if err != nil {
		log.Warnf("Client load user info fail with %v", err)
		err = fmt.Errorf("load user fail")
		return
	}
	ret = &UserinfoBack{}
	err = json.Unmarshal([]byte(data), ret)
	if err != nil {
		return
	}
	if ret.Code > 0 {
		err = fmt.Errorf("errcode:%v,errmsg:%v", ret.Code, ret.Message)
	}
	return
}

func (c *Client) LoadTicket(key, ticketType, accessToken string) (ret *TicketReturn, err error) {
	var conf = c.Conf[key]
	if conf == nil {
		err = fmt.Errorf("conf not found by key(%v)", key)
		return
	}
	var data string
	for i := 0; i < 5; i++ {
		data, err = xhttp.GetText("%v/cgi-bin/ticket/getticket?access_token=%v&type=%v", c.WeixinAPIServer, accessToken, ticketType)
		if err == nil {
			break
		}
	}
	if err != nil {
		log.Warnf("Client load ticket fail with %v", err)
		err = fmt.Errorf("load ticket fail")
		return
	}
	ret = &TicketReturn{}
	err = json.Unmarshal([]byte(data), ret)
	return
}

func (c *Client) CreateOrderV(args *OrderArgs, conf *Conf) (AnyArgs, error) {
	args.Appid, args.Mchid = conf.Appid, conf.Mchid
	args.SetSign(conf)
	var bys, err = xml.Marshal(args)
	if err != nil {
		err = fmt.Errorf("Client.CreateOrder  marshal fail with error(%v)", err)
		return nil, err
	}
	slog("Client.CreateOrder(Weixin) do create order by data:\n%v", string(bys))
	res, err := xhttp.PostTypeText("application/xml", bytes.NewBuffer(bys), "%v", c.UnifiedOrder)
	if err != nil {
		err = fmt.Errorf("Client.CreateOrder post wexin(%v) fail with error(%v)", c.UnifiedOrder, err)
		return nil, err
	}
	var ores = AnyArgs{}
	err = xml.Unmarshal([]byte(res), &ores)
	if err != nil {
		err = fmt.Errorf("Client.CreateOrder xml unmarshal with data(\n%v\n) fail with error(%v)", res, err)
		return nil, err
	}
	if ores["return_code"] != "SUCCESS" || ores["result_code"] != "SUCCESS" {
		err = fmt.Errorf("Client.CreateOrder weixin creat order by data(\n%v\n) fail with code(%v)error(%v)->%v",
			string(bys), ores["return_code"], ores["return_msg"], converter.JSON(ores))
		return nil, err
	}
	err = ores.VerifySign(conf, ores["sign"])
	if err != nil {
		err = fmt.Errorf("Client.CreateOrder verify sign with data(\n%v\n) fail with error(%v)", res, err)
		return nil, err
	}
	return ores, err
}

func (c *Client) Query(args *OrderQueryArgs, conf *Conf) (AnyArgs, error) {
	args.Appid, args.Mchid = conf.Appid, conf.Mchid
	args.SetSign(conf)
	var bys, err = xml.Marshal(args)
	if err != nil {
		err = fmt.Errorf("Client.CreateOrder  marshal fail with error(%v)", err)
		return nil, err
	}
	res, err := xhttp.PostTypeText("text/xml", bytes.NewBuffer(bys), "%v", c.QueryOrder)
	if err != nil {
		err = fmt.Errorf("Client.CreateOrder post wexin(%v) fail with error(%v)", c.UnifiedOrder, err)
		return nil, err
	}
	var ores = AnyArgs{}
	err = xml.Unmarshal([]byte(res), &ores)
	if err != nil {
		err = fmt.Errorf("Client.CreateOrder xml unmarshal with data(%v) fail with error(%v)", res, err)
		return nil, err
	}
	err = ores.VerifySign(conf, ores["sign"])
	if err != nil {
		err = fmt.Errorf("Client.CreateOrder verify sign with data(%v) fail with error(%v)", res, err)
		return nil, err
	}
	return ores, err
}

func (c *Client) CreateRefundOrderV(args *RefundArgs, conf *Conf) (AnyArgs, error) {
	args.Appid, args.Mchid = conf.Appid, conf.Mchid
	args.SetSign(conf)
	var bys, err = xml.Marshal(args)
	if err != nil {
		err = fmt.Errorf("Client.CreateRefundOrderV  marshal fail with error(%v)", err)
		return nil, err
	}
	slog("Client.CreateRefundOrderV(Weixin) do create order by data:\n%v", string(bys))
	req, err := http.NewRequest("POST", c.RefundOrder, bytes.NewBuffer(bys))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/xml")
	response, err := conf.PayClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	res, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 200 {
		err = fmt.Errorf("Client.CreateRefundOrderV post wexin(%v) fail with error(response code %v)", c.UnifiedOrder, response.StatusCode)
		return nil, err
	}
	var anyArgs = AnyArgs{}
	err = xml.Unmarshal(res, &anyArgs)
	if err != nil {
		err = fmt.Errorf("Client.CreateRefundOrderV xml unmarshal with data(\n%v\n) fail with error(%v)", res, err)
		return nil, err
	}
	if anyArgs["return_code"] != "SUCCESS" || anyArgs["result_code"] != "SUCCESS" {
		err = fmt.Errorf("Client.CreateRefundOrderV weixin creat order by data(\n%v\n) fail with code(%v)error(%v)->\n%v",
			string(bys), anyArgs["return_code"], anyArgs["return_msg"], string(res))
		return nil, err
	}
	err = anyArgs.VerifySign(conf, anyArgs["sign"])
	if err != nil {
		err = fmt.Errorf("Client.CreateRefundOrderV verify sign with data(\n%v\n) fail with error(%v)", res, err)
		return nil, err
	}
	return anyArgs, err
}

func (c *Client) PayNotifyH(hs *web.Session) web.Result {
	_, key := path.Split(hs.R.URL.Path)
	var addr = hs.R.Header.Get("X-Real-IP")
	if len(addr) < 1 {
		addr = hs.R.RemoteAddr
	}
	log.Debugf("Client.PayNotifyH(Weixin) receive notify on %v from %v", key, addr)
	var res = &NotifyBack{}
	defer func() {
		bys, _ := xml.Marshal(res)
		hs.W.Write(bys)
	}()
	conf := c.Conf[key]
	if conf == nil {
		err := fmt.Errorf("conf not found by key(%v)", key)
		log.Errorf("Client.PayNotifyH(Weixin) notify fail with error(%v)", err)
		res.ReturnCode = "FAIL"
		res.ReturnMsg = err.Error()
		return web.Return
	}
	var anyArgs = AnyArgs{}
	var bys, err = hs.RecvXML(&anyArgs)
	if err != nil {
		log.Errorf("Client.PayNotifyH(Weixin) %v", err)
		res.ReturnCode = "FAIL"
		res.ReturnMsg = err.Error()
		return web.Return
	}
	err = anyArgs.VerifySign(conf, anyArgs["sign"])
	if err != nil {
		log.Errorf("Client.PayNotifyH(Weixin) verify fail with error(%v)->\n%v", err, string(bys))
		res.ReturnCode = "FAIL"
		res.ReturnMsg = err.Error()
		return web.Return
	}
	var native = &PayNotifyArgs{}
	err = xml.Unmarshal(bys, native)
	if err != nil {
		log.Errorf("Client.PayNotifyH(Weixin) parse xml to object fail with error(%v)->\n%v", err, string(bys))
		res.ReturnCode = "FAIL"
		res.ReturnMsg = err.Error()
		return web.Return
	}
	slog("Client.PayNotifyH(Weixin) receive verified notify from address(%v), the data is:\n%v", addr, string(bys))
	err = c.H.OnPayNotify(c, hs, native)
	if err == nil {
		res.ReturnCode = "SUCCESS"
		res.ReturnMsg = "OK"
		return web.Return
	}
	log.Errorf("Client.PayNotifyH(Weixin) notify fail with error(%v)->\n%v", err, string(bys))
	res.ReturnCode = "FAIL"
	res.ReturnMsg = err.Error()
	return web.Return
}

func (c *Client) ManualPayNotifyH(hs *web.Session) web.Result {
	_, key := path.Split(hs.R.URL.Path)
	conf := c.Conf[key]
	if conf == nil {
		err := fmt.Errorf("conf not found by key(%v)", key)
		log.Errorf("Client.PayNotifyH(Weixin) manual pay notify fail with error(%v)", err)
		return hs.SendJSON(map[string]interface{}{
			"code": 10,
			"err":  err,
		})
	}
	username, password, ok := hs.R.BasicAuth()
	if !(len(conf.ManualUsername) > 0 && ok && username == conf.ManualUsername && password == conf.ManualPassword) {
		err := fmt.Errorf("auth fail by key(%v)", key)
		return hs.SendJSON(map[string]interface{}{
			"code": 401,
			"err":  err,
		})
	}
	var native = &PayNotifyArgs{}
	bys, err := hs.RecvXML(native)
	if err != nil {
		return hs.SendJSON(map[string]interface{}{
			"code": 1,
			"err":  err,
		})
	}
	var addr = hs.R.Header.Get("X-Real-IP")
	if len(addr) < 1 {
		addr = hs.R.RemoteAddr
	}
	log.Warnf("WeixinClient recieve manual pay notify for out_trade_no(%v) from %v", native.OutTradeNo, addr)
	err = c.H.OnPayNotify(c, hs, native)
	if err != nil {
		log.Errorf("Client.PayNotifyH(Weixin) notify fail with error(%v)->\n%v", err, string(bys))
		return hs.SendJSON(map[string]interface{}{
			"code": 2,
			"err":  err,
		})
	}
	return hs.SendJSON(map[string]interface{}{
		"code": 0,
		"data": "ok",
	})
}

func (c *Client) RefundNotifyH(hs *web.Session) web.Result {
	_, key := path.Split(hs.R.URL.Path)
	var addr = hs.R.Header.Get("X-Real-IP")
	if len(addr) < 1 {
		addr = hs.R.RemoteAddr
	}
	log.Debugf("Client.RefundNotifyH(Weixin) receive notify on %v from %v", key, addr)
	var res = &NotifyBack{}
	defer func() {
		bys, _ := xml.Marshal(res)
		hs.W.Write(bys)
	}()
	conf := c.Conf[key]
	if conf == nil {
		err := fmt.Errorf("conf not found by key(%v)", key)
		log.Errorf("Client.RefundNotifyH(Weixin) notify fail with error(%v)", err)
		res.ReturnCode = "FAIL"
		res.ReturnMsg = err.Error()
		return web.Return
	}
	var refundInfo = &RefundNotifyInfo{}
	var bys, err = hs.RecvXML(&refundInfo)
	if err != nil {
		log.Errorf("Client.RefundNotifyH(Weixin) %v", err)
		res.ReturnCode = "FAIL"
		res.ReturnMsg = err.Error()
		return web.Return
	}
	native, err := refundInfo.Decrypt(conf)
	if err != nil {
		log.Errorf("Client.RefundNotifyH(Weixin) verify fail with error(%v)->\n%v", err, string(bys))
		res.ReturnCode = "FAIL"
		res.ReturnMsg = err.Error()
		return web.Return
	}
	slog("Client.RefundNotifyH(Weixin) receive verify notify from address(%v), the data is:\n%v", addr, string(bys))
	err = c.H.OnRefundNotify(c, hs, native)
	if err == nil {
		res.ReturnCode = "SUCCESS"
		res.ReturnMsg = "OK"
		return web.Return
	}
	log.Errorf("Client.RefundNotifyH(Weixin) notify fail with error(%v)->\n%v", err, string(bys))
	res.ReturnCode = "FAIL"
	res.ReturnMsg = err.Error()
	return web.Return
}

func (c *Client) LoadJsapiSignature(key, turl string) (appid, mpAppid, noncestr, timestamp, signature string, err error) {
	var conf = c.Conf[key]
	if conf == nil {
		err = fmt.Errorf("conf not found by key(%v)", key)
		return
	}
	c.jsapiTicketLck.Lock()
	defer c.jsapiTicketLck.Unlock()
	conn := rediscache.C()
	defer conn.Close()
	vals, err := redis.Strings(conn.Do(
		"MGET",
		fmt.Sprintf("%v_timestamp", key),
		fmt.Sprintf("%v_jsapi_ticket", key),
	))
	if err != nil {
		return
	}
	appid = conf.Appid
	mpAppid = conf.MpAppid
	noncestr = uuid.New()
	now := time.Now().Local().UnixNano() / 1e6
	timestamp = fmt.Sprintf("%v", now/1000)
	ts, _ := strconv.ParseInt(vals[0], 10, 64)
	ticket := ""
	if now-ts*1000 < c.AccessTokenTimeout && len(vals[1]) > 0 {
		ticket = vals[1]
	} else {
		for i := 0; i < 2; i++ {
			var accessToken *AccessTokenReturn
			accessToken, err = c.LoadBaseAccessToken(key, i == 0)
			if err != nil {
				return
			}
			var ticketVal *TicketReturn
			ticketVal, err = c.LoadTicket(key, "jsapi", accessToken.AccessToken)
			if err != nil {
				return
			}
			if i == 0 && ticketVal.Code == 40001 {
				continue
			}
			if ticketVal.Code != 0 {
				err = fmt.Errorf("ret %v", converter.JSON(ticketVal))
				return
			}
			ticket = ticketVal.Ticket
			_, err = conn.Do(
				"MSET",
				fmt.Sprintf("%v_timestamp", key), timestamp,
				fmt.Sprintf("%v_jsapi_ticket", key), ticket,
			)
			if err != nil {
				return
			}
			break
		}
	}
	murl, _ := url.QueryUnescape(turl)
	data := "jsapi_ticket=" + ticket + "&noncestr=" + noncestr + "&timestamp=" + timestamp + "&url=" + murl
	log.Debugf("load jsapi signature by %v", data)
	signature = tools.SHA1([]byte(data))
	return
}

func (c *Client) MessageSend(key string, template *MpTemplateMessage) (err error) {
	args := converter.JSON(template)
	var accessToken *AccessTokenReturn
	for i := 0; i < 2; i++ {
		accessToken, err = c.LoadBaseAccessToken(key, i == 0)
		if err != nil {
			return
		}
		var data xmap.Valuable
		for i := 0; i < 5; i++ {
			data, err = xhttp.PostTypeMap(
				"application/json;charset=utf-8", bytes.NewBufferString(args),
				"https://api.weixin.qq.com/cgi-bin/message/template/send?access_token=%v",
				accessToken.AccessToken,
			)
			if err == nil {
				break
			}
		}
		if err != nil {
			log.Warnf("Client uniform send fail with %v", err)
			err = fmt.Errorf("uniform send fail")
			return
		}
		if i == 0 && data.Int("errcode") == 40001 {
			continue
		}
		if data.Int("errcode") != 0 {
			err = fmt.Errorf("ret %v, args \n%v", converter.JSON(data), args)
		}
		break
	}
	return
}

func (c *Client) UniformSendRunner() {
	log.Infof("UniformSendRunner is starting...")
	c.UniformSendRunning = true
	for c.UniformSendRunning {
		args := <-c.UniformSendQueue
		err := c.MessageSend(args.Key, &args.Message)
		if err != nil {
			log.Warnf("UniformSendRunner send message by key:%v,message:%v fail with %v", args.Key, converter.JSON(args.Message), err)
		} else {
			log.Debugf("UniformSendRunner send message by key:%v,message:%v is success", args.Key, converter.JSON(args.Message))
		}
	}
	log.Infof("UniformSendRunner is stopped")
}

func (c *Client) Hand(pre string, mux *web.SessionMux) {
	c.Pre = pre
	mux.HandleFunc("^"+pre+"/notify/pay/[^/]*(\\?.*)?$", c.PayNotifyH)
	mux.HandleFunc("^"+pre+"/manual/pay/[^/]*(\\?.*)?$", c.ManualPayNotifyH)
	mux.HandleFunc("^"+pre+"/notify/refund/[^/]*(\\?.*)?$", c.RefundNotifyH)
	mux.HandleNormal("^"+pre+"/qr.*$", http.StripPrefix(pre+"/qr", http.FileServer(http.Dir(c.Tmp))))
}

func AesCbcDecrypt(key, encrypted, iv string) (decrypted string, err error) {
	keyData, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return
	}
	encryptedData, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return
	}
	ivData, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return
	}
	decryptedData := make([]byte, len(encryptedData))
	chiper, err := aes.NewCipher(keyData)
	if err != nil {
		return
	}
	mode := cipher.NewCBCDecrypter(chiper, ivData)
	mode.CryptBlocks(decryptedData, encryptedData)
	decryptedData = PKCS7UnPadding(decryptedData)
	decrypted = string(decryptedData)
	return
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

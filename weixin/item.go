package weixin

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/Centny/tps/tools"
	"github.com/codingeasygo/util/uuid"

	"github.com/codingeasygo/util/converter"
)

const (
	TT_JSAPI  = "JSAPI"
	TT_NATIVE = "NATIVE"
	TT_APP    = "APP"
)

type OrderArgs struct {
	XMLName xml.Name `xml:"xml"`
	// appid	 appid  是	String(32)	wxd678efh567hg6787	微信分配的公众账号ID（企业号corpid即为此appId）
	Appid string `xml:"appid,omitempty"`
	// 商户号	mch_id	是	String(32)	1230000109	微信支付分配的商户号
	Mchid string `xml:"mch_id,omitempty"`
	// 随机字符串	nonce_str 	是	String(32)	5K8264ILTKCH16CQ2502SI8ZNMTM67VS	随机字符串，不长于32位
	NonceStr string `xml:"nonce_str,omitempty"`
	// 签名	sign	是	String(32)	C380BEC2BFD727A4B6845133519F3AD6	签名，详见签名生成算法
	Sign string `xml:"sign,omitempty"`
	// 商品描述	body	是	String(32)	Ipad mini  16G  白色	商品或支付单简要描述
	Body string `xml:"body,omitempty"`
	// 商户订单号	out_trade_no	是	String(32)	20150806125346	商户系统内部的订单号,32个字符内、可包含字母, 其他说明见商户订单号
	OutTradeNo string `xml:"out_trade_no,omitempty"`
	// 总金额	 total_fee	是	Int	888	订单总金额，单位为分，详见支付金额
	//Total_fee int64 `xml:"total_fee"`
	TotalFee int `xml:"total_fee,omitempty"`
	// 终端IP	spbill_create_ip	是	String(16)	123.12.12.123	APP和网页支付提交用户端ip，Native支付填调用微信支付API的机器IP。
	SpbillCreateIP string `xml:"spbill_create_ip,omitempty"`
	// 通知地址	notify_url	是	String(256)	http://www.weixin.qq.com/wxpay/pay.php	接收微信支付异步通知回调地址
	NotifyURL string `xml:"notify_url,omitempty"`
	// 交易类型	trade_type	是	String(16)	JSAPI	取值如下：JSAPI，NATIVE，APP，详细说明见参数规定
	TradeType string `xml:"trade_type,omitempty"`
	// 商品ID	product_id	否	String(32)	12235413214070356458058	trade_type=NATIVE，此参数必传。此id为二维码中包含的商品ID，商户自行定义。
	ProductID string `xml:"product_id,omitempty"`
	// 设备号	device_info	否	String(32)	013467007045764	终端设备号(门店号或收银设备ID)，注意：PC网页或公众号内支付请传"WEB"
	DeviceInfo string `xml:"device_info,omitempty"`
	// 商品详情	detail	否	String(8192)	Ipad mini  16G  白色	商品名称明细列表
	Detail string `xml:"detail,omitempty"`
	// 附加数据	attach	否	String(127)	深圳分店	附加数据，在查询API和支付通知中原样返回，该字段主要用于商户携带订单的自定义数据
	Attach string `xml:"attach,omitempty"`
	// 货币类型	fee_type	否	String(16)	CNY	符合ISO 4217标准的三位字母代码，默认人民币：CNY，其他值列表详见货币类型
	FeeType string `xml:"fee_type,omitempty"`
	// 交易起始时间	time_start	否	String(14)	20091225091010	订单生成时间，格式为yyyyMMddHHmmss，如2009年12月25日9点10分10秒表示为20091225091010。其他详见时间规则
	TimeStart string `xml:"time_start,omitempty"`
	// 交易结束时间	time_expire	否	String(14)	20091227091010
	// 订单失效时间，格式为yyyyMMddHHmmss，如2009年12月27日9点10分10秒表示为20091227091010。其他详见时间规则
	// 注意：最短失效时间间隔必须大于5分钟
	TimeExpire string `xml:"time_expire,omitempty"`
	// 商品标记	goods_tag	否	String(32)	WXG	商品标记，代金券或立减优惠功能的参数，说明详见代金券或立减优惠
	GoodsTag string `xml:"goods_tag,omitempty"`
	// 指定支付方式	limit_pay	否	String(32)	no_credit	no_credit--指定不能使用信用卡支付
	LimitPay string `xml:"limit_pay,omitempty"`
	// 用户标识	openid	否	String(128)	oUpF8uMuAJO_M2pxb1Q9zNjWeS6o	trade_type=JSAPI，此参数必传，用户在商户appid下的唯一标识。openid如何获取，可参考【获取openid】。企业号请使用【企业号OAuth2.0接口】获取企业号内成员userid，再调用【企业号userid转openid接口】进行转换
	Openid string `xml:"openid,omitempty"`
}

func (o *OrderArgs) SetDetail(goods []*Goods) {
	o.Detail = converter.JSON(map[string]interface{}{
		"goods_detail": goods,
	})
}

func (o *OrderArgs) SetSign(conf *Conf) {
	o.NonceStr = strings.ToUpper(uuid.New())
	o.Sign = conf.Md5SignV(o)
}

func (o *OrderArgs) ToXml() string {
	var o_val = reflect.ValueOf(o).Elem()
	var o_typ = reflect.TypeOf(o).Elem()
	var fields_l = o_typ.NumField()
	var strs string
	for i := 0; i < fields_l; i++ {
		var field = o_typ.Field(i)
		var key = field.Tag.Get("xml")
		key = strings.Split(key, ",")[0]
		var val = fmt.Sprintf("%v", o_val.Field(i))
		if len(val) < 1 {
			continue
		}
		strs = strs + fmt.Sprintf("<%v>%v</%v>", key, val, key)
	}
	return fmt.Sprintf("<xml>%v</xml>", strs)
}

type Goods struct {
	GoodsId       string  `json:"goods_id"`
	WxpayGoodsId  string  `json:"wxpay_goods_id"`
	GoodsName     string  `json:"goods_name"`
	GoodsNum      int     `json:"goods_num"`
	Price         float64 `json:"price"`
	GoodsCategory string  `json:"goods_category"`
	Body          string  `json:"body"`
}

type PayNotifyArgs struct {
	// 返回状态码	return_code	是	String(16)	SUCCESS
	// SUCCESS/FAIL
	// 此字段是通信标识，非交易标识，交易是否成功需要查看result_code来判断
	ReturnCode string `xml:"return_code"`
	// 返回信息	return_msg	否	String(128)	签名失败
	// 返回信息，如非空，为错误原因
	// 签名失败
	// 参数格式校验错误
	ReturnMsg string `xml:"return_msg"`
	// 公众账号ID	appid	是	String(32)	wx8888888888888888	微信分配的公众账号ID（企业号corpid即为此appId）
	Appid string `xml:"appid"`
	// 商户号	mch_id	是	String(32)	1900000109	微信支付分配的商户号
	Mchid string `xml:"mch_id"`
	// 设备号	device_info	否	String(32)	013467007045764	微信支付分配的终端设备号，
	DeviceInfo string `xml:"device_info"`
	// 随机字符串	nonce_str	是	String(32)	5K8264ILTKCH16CQ2502SI8ZNMTM67VS	随机字符串，不长于32位
	NonceStr string `xml:"nonce_str"`
	// 签名	sign	是	String(32)	C380BEC2BFD727A4B6845133519F3AD6	签名，详见签名算法
	Sign string `xml:"sign"`
	// 业务结果	result_code	是	String(16)	SUCCESS	SUCCESS/FAIL
	ResultCode string `xml:"result_code"`
	// 错误代码	err_code	否	String(32)	SYSTEMERROR	错误返回的信息描述
	ErrCode string `xml:"err_code"`
	// 错误代码描述	err_code_des	否	String(128)	系统错误	错误返回的信息描述
	ErrCodeDes string `xml:"err_code_des"`
	// 用户标识	openid	是	String(128)	wxd930ea5d5a258f4f	用户在商户appid下的唯一标识
	Openid string `xml:"openid"`
	// 是否关注公众账号	is_subscribe	否	String(1)	Y	用户是否关注公众账号，Y-关注，N-未关注，仅在公众账号类型支付有效
	IsSubscribe string `xml:"is_subscribe"`
	// 交易类型	trade_type	是	String(16)	JSAPI	JSAPI、NATIVE、APP
	TradeType string `xml:"trade_type"`
	// 付款银行	bank_type	是	String(16)	CMC	银行类型，采用字符串类型的银行标识，银行类型见银行列表
	BankType string `xml:"bank_type"`
	// 总金额	total_fee	是	Int	100	订单总金额，单位为分
	TotalFee int `xml:"total_fee"`
	// 货币种类	fee_type	否	String(8)	CNY	货币类型，符合ISO4217标准的三位字母代码，默认人民币：CNY，其他值列表详见货币类型
	FeeType string `xml:"fee_type"`
	// 现金支付金额	cash_fee	是	Int	100	现金支付金额订单现金支付金额，详见支付金额
	CashFee int `xml:"cash_fee"`
	// 现金支付货币类型	cash_fee_type	否	String(16)	CNY	货币类型，符合ISO4217标准的三位字母代码，默认人民币：CNY，其他值列表详见货币类型
	CashFeeType string `xml:"cash_fee_type"`
	// 代金券或立减优惠金额	coupon_fee	否	Int	10	代金券或立减优惠金额<=订单总金额，订单总金额-代金券或立减优惠金额=现金支付金额，详见支付金额
	CouponFee string `xml:"coupon_fee"`
	// 代金券或立减优惠使用数量	coupon_count	否	Int	1	代金券或立减优惠使用数量
	CouponCount string `xml:"coupon_count"`
	// 代金券或立减优惠ID	coupon_id_$n	否	String(20)	10000	代金券或立减优惠ID,$n为下标，从0开始编号
	CouponID1 string `xml:"coupon_id_1"`
	// 单个代金券或立减优惠支付金额	coupon_fee_$n	否	Int	100	单个代金券或立减优惠支付金额,$n为下标，从0开始编号
	CouponFee1 string `xml:"coupon_fee_1"`
	// 微信支付订单号	transaction_id	是	String(32)	1217752501201407033233368018	微信支付订单号
	TransactionID string `xml:"transaction_id"`
	// 商户订单号	out_trade_no	是	String(32)	1212321211201407033568112322	商户系统的订单号，与请求一致。
	OutTradeNo string `xml:"out_trade_no"`
	// 商家数据包	attach	否	String(128)	123456	商家数据包，原样返回
	Attach string `xml:"attach"`
	// 支付完成时间	time_end	是	String(14)	20141030133525	支付完成时间，格式为yyyyMMddHHmmss，如2009年12月25日9点10分10秒表示为20091225091010。其他详见时间规则
	TimeEnd string `xml:"time_end"`
}

func (p *PayNotifyArgs) VerifySign(conf *Conf, sign string) error {
	var tsign = conf.Md5SignV(p)
	if tsign == sign {
		return nil
	}
	return fmt.Errorf("md5 verify fail")
}

type RefundNotifyInfo struct {
	// 返回状态码	return_code	是	String(16)	SUCCESS
	// SUCCESS/FAIL
	// 此字段是通信标识，非交易标识，交易是否成功需要查看result_code来判断
	ReturnCode string `xml:"return_code"`
	// 返回信息	return_msg	否	String(128)	签名失败
	// 返回信息，如非空，为错误原因
	// 签名失败
	// 参数格式校验错误
	ReturnMsg string `xml:"return_msg"`
	// 公众账号ID	appid	是	String(32)	wx8888888888888888	微信分配的公众账号ID（企业号corpid即为此appId）
	Appid string `xml:"appid"`
	// 商户号	mch_id	是	String(32)	1900000109	微信支付分配的商户号
	Mchid string `xml:"mch_id"`
	// 随机字符串	nonce_str	是	String(32)	5K8264ILTKCH16CQ2502SI8ZNMTM67VS	随机字符串，不长于32位
	NonceStr string `xml:"nonce_str"`
	// 签名	sign	是	String(32)	C380BEC2BFD727A4B6845133519F3AD6	签名，详见签名算法
	ReqInfo string `xml:"req_info"`
}

func (r *RefundNotifyInfo) Decrypt(conf *Conf) (args *RefundNotifyArgs, err error) {
	ciphertext, err := base64.StdEncoding.DecodeString(r.ReqInfo)
	if err != nil {
		return
	}
	key := tools.MD5([]byte(conf.PaySecret))
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return
	}
	dst := make([]byte, len(ciphertext))
	remain := 0
	for remain < len(ciphertext) {
		block.Decrypt(dst[remain:], ciphertext[remain:])
		remain += block.BlockSize()
	}
	args = &RefundNotifyArgs{}
	err = xml.Unmarshal(dst, args)
	return
}

type RefundNotifyArgs struct {
	// 微信支付订单号	transaction_id	是	String(32)	1217752501201407033233368018	微信支付订单号
	TransactionID string `xml:"transaction_id"`
	// 商户订单号	out_trade_no	是	String(32)	1212321211201407033568112322	商户系统的订单号，与请求一致。
	OutTradeNo string `xml:"out_trade_no"`
	// 微信退款单号 refund_id
	RefundID string `xml:"refund_id" json:"refund_id"`
	// 商户退款单号
	OutRefundNo string `xml:"out_refund_no" json:"out_refund_no"`
	// 订单金额
	TotalFee int `xml:"total_fee" json:"total_fee"`
	// 应结订单金额
	SettlementTotalFee int `xml:"settlement_total_fee" json:"settlement_total_fee"`
	// 申请退款金额
	RefundFee int `xml:"refund_fee" json:"refund_fee"`
	// 退款状态
	RefundStatus string `xml:"refund_status" json:"refund_status"`
	// 退款成功时间
	SuccessTime string `xml:"success_time" json:"success_time"`
	// 退款入账账户
	RefundRecvAccout string `xml:"refund_recv_accout" json:"refund_recv_accout"`
	// 退款资金来源
	RefundAccount string `xml:"refund_account" json:"refund_account"`
	// 退款发起来源
	RefundRequestSource string `xml:"refund_request_source" json:"refund_request_source"`
}

type AnyArgs map[string]string

type xmlMapEntry struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

func (a *AnyArgs) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	*a = AnyArgs{}
	for {
		var e xmlMapEntry
		err := d.Decode(&e)
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		(*a)[e.XMLName.Local] = e.Value
	}
	return nil
}

func (a AnyArgs) VerifySign(conf *Conf, sign string) error {
	var tsign = conf.Md5SignV(a)
	if tsign == sign {
		return nil
	}
	return fmt.Errorf("md5 verify fail")
}

type NotifyBack struct {
	// 返回状态码	return_code	是	String(16)	SUCCESS
	// SUCCESS/FAIL
	// 此字段是通信标识，非交易标识，交易是否成功需要查看result_code来判断
	ReturnCode string `xml:"return_code"`
	// 返回信息	return_msg	否	String(128)	签名失败
	// 返回信息，如非空，为错误原因
	// 签名失败
	// 参数格式校验错误
	ReturnMsg string `xml:"return_msg"`
}

type OrderQueryArgs struct {
	// 	公众账号ID	appid	是	String(32)	wxd678efh567hg6787	微信分配的公众账号ID（企业号corpid即为此appId）
	Appid string `xml:"appid"`
	// 商户号	mch_id	是	String(32)	1230000109	微信支付分配的商户号
	Mchid string `xml:"mch_id"`
	// 微信订单号	transaction_id	二选一	String(32)	1009660380201506130728806387	微信的订单号，优先使用
	TransactionId string `xml:"transaction_id"`
	// 商户订单号	out_trade_no	String(32)	20150806125346	商户系统内部的订单号，当没提供transaction_id时需要传这个。
	OutTradeNo string `xml:"out_trade_no"`
	// 随机字符串	nonce_str	是	String(32)	C380BEC2BFD727A4B6845133519F3AD6	随机字符串，不长于32位。推荐随机数生成算法
	NonceStr string `xml:"nonce_str"`
	//时间戳	timestamp	String(10)	是	1412000000	时间戳，请见接口规则-参数规定
	Timestamp string `xml:"timestamp"`
	// 签名	sign	是	String(32)	5K8264ILTKCH16CQ2502SI8ZNMTM67VS	签名，详见签名生成算法
	Sign string `xml:"sign"`
}

func (o *OrderQueryArgs) SetSign(conf *Conf) {
	o.Sign = conf.Md5SignV(o)
}

type OrderAppArgs struct {
	Appid     string `xml:"appid" json:"appid"`         //	String(32)	是	wx8888888888888888	微信开放平台审核通过的应用APPID
	Partnerid string `xml:"partnerid" json:"partnerid"` //	String(32)	是	1900000109	微信支付分配的商户号
	Prepayid  string `xml:"prepayid" json:"prepayid"`   //	String(32)	是	WX1217752501201407033233368018	微信返回的支付交易会话ID
	Package   string `xml:"package" json:"package"`     //	String(128)	是	Sign=WXPay	暂填写固定值Sign=WXPay
	Noncestr  string `xml:"noncestr" json:"noncestr"`   //	String(32)	是	5K8264ILTKCH16CQ2502SI8ZNMTM67VS	随机字符串，不长于32位。推荐随机数生成算法
	Timestamp int64  `xml:"timestamp" json:"timestamp"` //	String(10)	是	1412000000	时间戳，请见接口规则-参数规定
	Sign      string `xml:"sign" json:"sign"`           //	String(32)	是	C380BEC2BFD727A4B6845133519F3AD6	签名，详见签名生成算法
}

func (o *OrderAppArgs) SetSign(conf *Conf) {
	o.Sign = conf.Md5SignV(o)
}

type OrderH5Args struct {
	Appid     string `xml:"appId" json:"appId"`         //公众号id	appId	是	String(16)	wx8888888888888888	商户注册具有支付权限的公众号成功后即可获得
	TimeStamp string `xml:"timeStamp" json:"timeStamp"` //时间戳	timeStamp	是	String(32)	1414561699	当前的时间，其他详见时间戳规则
	NonceStr  string `xml:"nonceStr" json:"nonceStr"`   //随机字符串	nonceStr	是	String(32)	5K8264ILTKCH16CQ2502SI8ZNMTM67VS	随机字符串，不长于32位。推荐随机数生成算法
	Package   string `xml:"package" json:"package"`     //订单详情扩展字符串	package	是	String(128)	prepay_id=123456789	统一下单接口返回的prepay_id参数值，提交格式如：prepay_id=***
	SignType  string `xml:"signType" json:"signType"`   //签名方式	signType	是	String(32)	MD5	签名算法，暂支持MD5
	PaySign   string `xml:"paySign" json:"paySign"`     //签名	paySign	是	String(64)	C380BEC2BFD727A4B6845133519F3AD6	签名，详见签名生成算法
}

func (o *OrderH5Args) SetSign(conf *Conf) {
	o.PaySign = conf.Md5SignV(o)
}

const (
	ScopeBase     = "snsapi_base"
	ScopeUserinfo = "snsapi_userinfo"
)

type AccessTokenReturn struct {
	UnionID      string `json:"unionid"`
	OpenID       string `json:"openid"`
	ExpiresIn    int    `json:"expires_in"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	Code         int    `json:"errcode"`
	Message      string `json:"errmsg"`
}

type Code2SessionReturn struct {
	UnionID    string `json:"unionid"`
	OpenID     string `json:"openid"`
	SessionKey string `json:"session_key"`
	Code       int    `json:"errcode"`
	Message    string `json:"errmsg"`
}

type TicketReturn struct {
	ExpiresIn int    `json:"expires_in"`
	Ticket    string `json:"ticket"`
	Code      int    `json:"errcode"`
	Message   string `json:"errmsg"`
}

type UserinfoBack struct {
	OpenID     string   `json:"openid"`
	Nickname   string   `json:"nickname"`
	Sex        int      `json:"sex"`
	Province   string   `json:"province"`
	City       string   `json:"city"`
	Country    string   `json:"country"`
	HeadImgURL string   `json:"headimgurl"`
	Privilege  []string `json:"privilege"`
	Unionid    string   `json:"unionid"`
	Scope      string   `json:"scope"`
	Code       int      `json:"errcode"`
	Message    string   `json:"errmsg"`
}

type EncryptedUserinfo struct {
	OpenID          string `json:"openId"`
	UnionID         string `json:"unionID"`
	AvatarURL       string `json:"avatarUrl"`
	City            string `json:"city"`
	Country         string `json:"country"`
	CountryCode     string `json:"86"`
	Gender          int    `json:"gender"`
	NickName        string `json:"nickName"`
	Province        string `json:"province"`
	PhoneNumber     string `json:"phoneNumber"`
	PurePhoneNumber string `json:"purePhoneNumber"`
}

func (e *EncryptedUserinfo) Decrypt(key, iv, encrypted string) (err error) {
	decrypted, err := AesCbcDecrypt(key, encrypted, iv)
	if err == nil {
		err = json.Unmarshal([]byte(decrypted), e)
	}
	return
}

type RefundArgs struct {
	XMLName xml.Name `xml:"xml"`
	//公众账号ID	appid	是	String(32)	wx8888888888888888	微信分配的公众账号ID（企业号corpid即为此appId）
	Appid string `xml:"appid" json:"appid"`
	//商户号	mch_id	是	String(32)	1900000109	微信支付分配的商户号
	Mchid string `xml:"mch_id" json:"mch_id"`
	//随机字符串	nonce_str	是	String(32)	5K8264ILTKCH16CQ2502SI8ZNMTM67VS
	//随机字符串，不长于32位。推荐随机数生成算法
	NonceStr string `xml:"nonce_str" json:"nonce_str"`
	//签名	sign	是	String(32)	C380BEC2BFD727A4B6845133519F3AD6	签名，详见签名生成算法
	Sign string `xml:"sign" json:"sign"`
	//签名类型	sign_type	否	String(32)	HMAC-SHA256	签名类型，目前支持HMAC-SHA256和MD5，默认为MD5
	SignType string `xml:"sign_type" json:"sign_type"`
	//微信订单号	transaction_id	二选一	String(32)	1217752501201407033233368018
	//微信生成的订单号，在支付通知中有返回
	TransactionID string `xml:"transaction_id" json:"transaction_id"`
	//商户订单号	out_trade_no	String(32)	1217752501201407033233368018
	//商户系统内部订单号，要求32个字符内，只能是数字、大小写字母_-|*@ ，且在同一个商户号下唯一。
	OutTradeNo string `xml:"out_trade_no" json:"out_trade_no"`
	//商户退款单号	out_refund_no	是	String(64)	1217752501201407033233368018
	//商户系统内部的退款单号，商户系统内部唯一，只能是数字、大小写字母_-|*@ ，同一退款单号多次请求只退一笔。
	OutRefundNo string `xml:"out_refund_no" json:"out_refund_no"`
	//订单金额	total_fee	是	Int	100	订单总金额，单位为分，只能为整数，详见支付金额
	TotalFee int `xml:"total_fee" json:"total_fee"`
	//退款金额	refund_fee	是	Int	100	退款总金额，订单总金额，单位为分，只能为整数，详见支付金额
	RefundFee int `xml:"refund_fee" json:"refund_fee"`
	//退款货币种类	refund_fee_type	否	String(8)	CNY	退款货币类型，需与支付一致，或者不填。
	//符合ISO 4217标准的三位字母代码，默认人民币：CNY，其他值列表详见货币类型
	RefundFeeType string `xml:"refund_fee_type" json:"refund_fee_type"`
	//退款原因	refund_desc	否	String(80)	商品已售完	若商户传入，会在下发给用户的退款消息中体现退款原因
	RefundDesc string `xml:"refund_desc" json:"refund_desc"`
	//退款资金来源	refund_account	否	String(30)
	// REFUND_SOURCE_RECHARGE_FUNDS 仅针对老资金流商户使用
	// REFUND_SOURCE_UNSETTLED_FUNDS---未结算资金退款（默认使用未结算资金退款）
	// REFUND_SOURCE_RECHARGE_FUNDS---可用余额退款
	RefundAccount string `xml:"refund_account" json:"refund_account"`
	//退款结果通知url	notify_url	否	String(256)	https://weixin.qq.com/notify/
	//异步接收微信支付退款结果通知的回调地址，通知URL必须为外网可访问的url，不允许带参数，
	//如果参数中传了notify_url，则商户平台上配置的回调地址将不会生效。
	NotifyURL string `xml:"notify_url" json:"notify_url"`
}

func (r *RefundArgs) SetSign(conf *Conf) {
	r.Sign = conf.Md5SignV(r)
}

type QueryRefundArgs struct {
	// 公众账号ID	appid	是	String(32)	wx8888888888888888	微信支付分配的公众账号ID（企业号corpid即为此appId）
	Appid string `xml:"appid" json:"appid"`
	// 商户号	mch_id	是	String(32)	1900000109	微信支付分配的商户号
	Mchid string `xml:"mch_id" json:"mch_id"`
	// 随机字符串	nonce_str	是	String(32)	5K8264ILTKCH16CQ2502SI8ZNMTM67VS	随机字符串，不长于32位。推荐随机数生成算法
	NonceStr string `xml:"nonce_str" json:"nonce_str"`
	// 签名	sign	是	String(32)	C380BEC2BFD727A4B6845133519F3AD6	签名，详见签名生成算法
	Sign string `xml:"sign" json:"sign"`
	// 签名类型	sign_type	否	String(32)	HMAC-SHA256	签名类型，目前支持HMAC-SHA256和MD5，默认为MD5
	SignType string `xml:"sign_type" json:"sign_type"`
	// 微信订单号	transaction_id	四选一	String(32)	1217752501201407033233368018
	// 微信订单号查询的优先级是： refund_id > out_refund_no > transaction_id > out_trade_no
	TransactionID string `xml:"transaction_id" json:"transaction_id"`
	// 商户订单号	out_trade_no	String(32)	1217752501201407033233368018	商户系统内部订单号，要求32个字符内，只能是数字、大小写字母_-|*@ ，且在同一个商户号下唯一。
	OutTradeNo string `xml:"out_trade_no" json:"out_trade_no"`
	// 商户退款单号	out_refund_no	String(64)	1217752501201407033233368018	商户系统内部的退款单号，商户系统内部唯一，只能是数字、大小写字母_-|*@ ，同一退款单号多次请求只退一笔。
	OutRefundNo string `xml:"out_refund_no" json:"out_refund_no"`
	// 微信退款单号	refund_id	String(32)	1217752501201407033233368018
	// 微信生成的退款单号，在申请退款接口有返回
	RefundID string `xml:"refund_id" json:"refund_id"`
	// 偏移量	offset	否	Int	15
	// 偏移量，当部分退款次数超过10次时可使用，表示返回的查询结果从这个偏移量开始取记录
	Offset int `xml:"offset" json:"offset"`
}

type MpTemplateMessageMiniprogram struct {
	Appid string `json:"appid,omitempty"`
	Path  string `json:"path,omitempty"`
}

type MpTemplateMessageData struct {
	Value string `json:"value,omitempty"`
	Color string `json:"color,omitempty"`
}

type MpTemplateMessage struct {
	TemplateID  string                           `json:"template_id,omitempty"`
	URL         string                           `json:"url,omitempty"`
	ToUser      string                           `json:"touser"`
	Data        map[string]MpTemplateMessageData `json:"data,omitempty"`
	MiniProgram MpTemplateMessageMiniprogram     `json:"miniprogram,omitempty"`
}

type UniformSendArgs struct {
	Key     string            `json:"-"`
	Message MpTemplateMessage `json:"message"`
}

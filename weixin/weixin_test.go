package weixin

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"testing"

	"github.com/Centny/gwf/routing/httptest"

	"github.com/Centny/gwf/routing"
	"github.com/Centny/gwf/util"
)

type test_h struct {
}

func (t *test_h) OnNotify(c *Client, hs *routing.HTTPSession, nativ *NaviteNotifyArgs) error {
	return nil
}

func TestWeixin(t *testing.T) {
	// var wx = NewClient(
	// 	"https://api.mch.weixin.qq.com/pay/unifiedorder",
	// 	"https://api.mch.weixin.qq.com/pay/orderquery",
	// 	"",
	// 	&test_h{},
	// )
	// wx.Native.Load(
	// 	"wxd8ed718345ac5d25", "1313941701",
	// 	"rp6h3aavmbcll1newi9jdqzfkjfl5ue8", "4d3dcb022f2dc53531bc881b23adcf79",
	// )
	// var abc = &Conf{}
	// abc.Load(
	// 	"wxd8ed718345ac5d25", "1313941701",
	// 	"rp6h3aavmbcll1newi9jdqzfkjfl5ue8", "4d3dcb022f2dc53531bc881b23adcf79",
	// )
	// wx.App["abc"] = abc
	// ord, err := wx.CreateNativeOrder("http://wewx.sc", tools.NewOno(), "kfskf", 0.01)
	// if err != nil {
	// 	t.Error(err)
	// 	return
	// }
	// fmt.Println("code_url->", ord.CodeUrl)
	// fmt.Println(wx.CreateOrderAppArgs("abc", ord))
}

func TestVersion(t *testing.T) {
	var data = `
<xml><appid><![CDATA[wxd8ed718345ac5d25]]></appid>
<bank_type><![CDATA[CFT]]></bank_type>
<cash_fee><![CDATA[335]]></cash_fee>
<coupon_count><![CDATA[1]]></coupon_count>
<coupon_fee>15</coupon_fee>
<coupon_fee_0><![CDATA[15]]></coupon_fee_0>
<coupon_id_0><![CDATA[2000000036525300106]]></coupon_id_0>
<fee_type><![CDATA[CNY]]></fee_type>
<is_subscribe><![CDATA[N]]></is_subscribe>
<mch_id><![CDATA[1313941701]]></mch_id>
<nonce_str><![CDATA[5B35D1D7E13823185E000033]]></nonce_str>
<openid><![CDATA[ocC1EuJ3Z5o-jOh1WyeADwkwfzQo]]></openid>
<out_trade_no><![CDATA[201806291429430000000030]]></out_trade_no>
<result_code><![CDATA[SUCCESS]]></result_code>
<return_code><![CDATA[SUCCESS]]></return_code>
<sign><![CDATA[E0DA50FDB9DEAEEFFE1798561F9F591C]]></sign>
<time_end><![CDATA[20180629142948]]></time_end>
<total_fee>350</total_fee>
<trade_type><![CDATA[JSAPI]]></trade_type>
<transaction_id><![CDATA[4200000120201806293440894332]]></transaction_id>
</xml>
	`
	var native = AnyNotifyArgs{}
	err := xml.Unmarshal([]byte(data), &native)
	if err != nil {
		t.Error(err)
		return
	}
	var wx = NewClient(
		"https://api.mch.weixin.qq.com/pay/unifiedorder",
		"https://api.mch.weixin.qq.com/pay/orderquery",
		"",
		&test_h{},
	)
	conf := &Conf{}
	conf.Load(
		"wxd8ed718345ac5d25", "1313941701",
		"rp6h3aavmbcll1newi9jdqzfkjfl5ue8", "8185c1cc480bf09b02813f09e4cf52fa",
	)
	wx.Conf["native"] = conf
	err = native.VerifySign(conf, fmt.Sprintf("%v", native["sign"]))
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("--->", native)
	ts := httptest.NewMuxServer()
	ts.Mux.HFunc("^/native.*$", wx.Notify)
	res, err := ts.PostN("/native", "text/xml", bytes.NewBufferString(data))
	fmt.Println(res, err)
}

func TestXx(t *testing.T) {
	var data = `
<xml>
   <appid>wx2421b1c4370ec43b</appid>
   <attach>支付测试</attach>
   <body>JSAPI支付测试</body>
   <mch_id>10000100</mch_id>
   <detail><![CDATA[{ "goods_detail":[ { "goods_id":"iphone6s_16G", "wxpay_goods_id":"1001", "goods_name":"iPhone6s 16G", "quantity":1, "price":528800, "goods_category":"123456", "body":"苹果手机" }, { "goods_id":"iphone6s_32G", "wxpay_goods_id":"1002", "goods_name":"iPhone6s 32G", "quantity":1, "price":608800, "goods_category":"123789", "body":"苹果手机" } ] }]]></detail>
   <nonce_str>1add1a30ac87aa2db72f57a2375d8fec</nonce_str>
   <notify_url>http://wxpay.weixin.qq.com/pub_v2/pay/notify.v2.php</notify_url>
   <openid>oUpF8uMuAJO_M2pxb1Q9zNjWeS6o</openid>
   <out_trade_no>1415659990</out_trade_no>
   <spbill_create_ip>14.23.150.211</spbill_create_ip>
   <total_fee>1</total_fee>
   <trade_type>JSAPI</trade_type>
   <sign>0CB01533B8C1EF103065174F50BCA001</sign>
</xml>
`
	fmt.Println(util.HPostN("https://api.mch.weixin.qq.com/pay/unifiedorder", "application/xml", bytes.NewBufferString(data)))
}

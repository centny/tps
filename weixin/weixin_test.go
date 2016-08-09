package weixin

import (
	"bytes"
	"fmt"
	"github.com/Centny/gwf/routing"
	"github.com/Centny/gwf/util"
	"github.com/Centny/tps/tools"
	"testing"
)

type test_h struct {
}

func (t *test_h) OnNotify(c *Client, hs *routing.HTTPSession, nativ *NaviteNotifyArgs) error {
	return nil
}

func TestWeixin(t *testing.T) {
	var wx = NewClient(
		"https://api.mch.weixin.qq.com/pay/unifiedorder",
		"https://api.mch.weixin.qq.com/pay/orderquery",
		"",
		&test_h{},
	)
	wx.Native.Load(
		"wxd8ed718345ac5d25", "1313941701",
		"rp6h3aavmbcll1newi9jdqzfkjfl5ue8", "4d3dcb022f2dc53531bc881b23adcf79",
	)
	ord, err := wx.CreateNativeOrder("http://wewx.sc", tools.NewOno(), "kfskf", 0.01)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("code_url->", ord.CodeUrl)
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

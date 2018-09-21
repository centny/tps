package alipay

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/Centny/gwf/routing"
	"github.com/Centny/gwf/routing/httptest"
)

type test_h struct {
}

func (t *test_h) OnNotify(c *Client, hs *routing.HTTPSession) error {
	return nil
}

func (t *test_h) OnReturn(c *Client, hs *routing.HTTPSession) routing.HResult {
	return routing.HRES_RETURN
}

func TestAlipay(t *testing.T) {
	var client = NewClient("https://mapi.alipay.com/gateway.do", &test_h{})
	client.C("web").Load(
		"2088501949844011",
		"itdayang@gmail.com",
		"",
		"viz4safb1zazb5bqeraujlg79agfcj02",
		`
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDAymEQFouLpQ7a8dhynKVLDD9T0yxjY9LeTQk0Y+97rf9sjk22
OdeNvVpTnEMd1GHjQL2GU/YFQOMG2gIbkLMUashQGkNGGUIQa/owF4Us3vIhaENw
gEWg3ybpuYwO2QVNXD3CpWwTuQ/KXllKq/n5M1vZgB7vzW5SW2Ll7tcwdQIDAQAB
AoGAA0Gn4BCxbLtuA86//DefJyRe0XiosEkYX77nX+YsPmeS/+9rap+Rf4hqRS1H
iPJ0cNVAHku+xRnye8Qk8vg/vhoE40HZqIp8cUAb2x/+V5hPYX8VT8Joby8y37kk
JwaSR4BbNq5r2h7OTmLAIyLBOCWfPIUxm092NS9N+Hh9gCECQQDvg3b0u3299yEo
tx9yz1rJo5DPQw/j/9lHI4/dlwmU7qgoitDD0CoHm57MDoP0rfodmqRQuu39WLvQ
RSAVsKjJAkEAzg+YdKOskpEQ5gqVpnPG1QX+zJ2q6IrJwoz3Vz7ApZuZuTMNQP6I
pRk+DwyYQjMLJZ9pWXMnQqrUZsXymvMMTQJBAN0Ed3UGvtXZgqPLuB198s03Pp3D
yJogsiPPUSauBY2FXW9sCZFoOiCjHjo2+tWC5dcDqLVGie7LPyTFZQIe7uECQQCh
9341CEXoOqBWwTEZ0d0SqhC6Up/5AsZN5rGv4QJZ6bFt8ePUF33ej7XI7HRtbGOx
odiT18CfVVl4otTr2GjtAkBlAFytEjIbtdpYDE1F7ANFoVFGy6jeCCs7re1D2BTp
pIGJlxkkxC/Loi2ZnztwbY/DbOCQpN9dvSEiwzsOQyWL
-----END RSA PRIVATE KEY-----
	`,
		"",
		`
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCnxj/9qwVfgoUh/y2W89L6BkRA
FljhNhgPdyPuBV64bfQNN1PjbCzkIM6qRdKBoLPXmKKMiFYnkd6rAoprih3/PrQE
B/VsW8OoM8fxn67UDYuyBTqA23MML9q1+ilIZwBC2AQ2UBVOrFXfFl75p6/B5Ksi
NG9zpgmLCUYuLkxpLQIDAQAB
-----END PUBLIC KEY-----
	`)
	fmt.Println(client.CreateUrl("web", "Web", "http://pb.dev.jxzy.com/_echo_", "http://pb.dev.jxzy.com/_echo_", "6843192280647119", "abcc", "223", 0.01))
	fmt.Println(client.CreateUrl("web", "APP", "http://pb.dev.jxzy.com/_echo_", "http://pb.dev.jxzy.com/_echo_", "6843192280647119", "abcc", "223", 0.01))
	var ts = httptest.NewMuxServer()
	// ts.Mux.HFunc("^/return(\\?.*)?$", client.Return)
	ts.Mux.HFunc("^/notify/web(\\?.*)?$", client.Notify)
	// fmt.Println(ts.G("/return?%v", "body=223&buyer_email=centny%40gmail.com&buyer_id=2088102972036594&exterface=create_direct_pay_by_user&is_success=T&notify_id=RqPnCoPT3K9%252Fvwbh3InWfjSquPZ53GKZDlpLiPerRyczkZ1BqSCeryalHBnmC%252FQ3uhhI&notify_time=2016-08-04+11%3A15%3A02&notify_type=trade_status_sync&out_trade_no=6843192280647112&payment_type=1&seller_email=itdayang%40gmail.com&seller_id=2088501949844011&subject=abcc&total_fee=0.01&trade_no=2016080421001004590289703858&trade_status=TRADE_SUCCESS&sign=f98956240273d3bda99b84c9a64c27a4&sign_type=MD5"))
	fmt.Println("xxxx->a")
	fmt.Println(ts.G("/notify/web?%v", url.QueryEscape("body=支付课程&buyer_email=1240001796@qq.com&buyer_id=2088302272527260&discount=0.00&gmt_create=2016-08-08 13:40:38&is_total_fee_adjust=Y&notify_id=0f64fed2e4d592d15ff093e08f7b526i0a&notify_time=2016-08-08 13:54:14&notify_type=trade_status_sync&out_trade_no=201608081334210000000004&payment_type=1&price=0.01&quantity=1&seller_email=itdayang@gmail.com&seller_id=2088501949844011&subject=酷校购买课程&total_fee=0.01&trade_no=2016080821001004260264757851&trade_status=WAIT_BUYER_PAY&use_coupon=N")))
}

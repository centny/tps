package alipay

import (
	"testing"

	"github.com/codingeasygo/web"
)

type test_h struct {
}

func (t *test_h) OnNotify(c *Client, hs *web.Session) error {
	return nil
}

func (t *test_h) OnReturn(c *Client, hs *web.Session) web.Result {
	return web.Return
}

func TestSome(t *testing.T) {

}

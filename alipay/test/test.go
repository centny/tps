package main

// import (
// 	"fmt"
// 	"github.com/Centny/alipay"
// 	"github.com/Centny/gwf/routing"
// )

// func main() {
// 	var client = alipay.NewClient("https://mapi.alipay.com/gateway.do", nil)
// 	client.Web.Load(
// 		"",
// 		"",
// 		"",
// 		`
// 	`,
// 		"",
// 		`
// 	`)
// 	fmt.Println(client.CreateWebUrl("http://cny.dev.gdy.io/notify", "http://cny.dev.gdy.io/return", "6843192280647512", "abcc", "223", 0.01))
// 	routing.HFunc("^/return(\\?.*)?$", client.Return)
// 	routing.HFunc("^/notify(\\?.*)?$", client.Notify)
// 	routing.ListenAndServe(":9834")

// }

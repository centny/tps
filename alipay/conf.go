package alipay

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/Centny/gwf/util"
)

type Conf struct {
	Partner string
	Seller  string
	MD5     string
	Private *rsa.PrivateKey
	Publish *rsa.PublicKey
	Alipay  *rsa.PublicKey
}

func (c *Conf) Load(partner, seller, md5, private, publish, alipay string) error {
	c.Partner, c.Seller, c.MD5 = partner, seller, md5
	var err error
	//
	private_b, _ := pem.Decode([]byte(private))
	if private_b == nil {
		return util.Err("decode private key fail")
	}
	c.Private, err = x509.ParsePKCS1PrivateKey(private_b.Bytes)
	if err != nil {
		return err
	}
	//
	var tmp interface{}
	if len(publish) > 0 {
		publish_b, _ := pem.Decode([]byte(publish))
		if publish_b == nil {
			return util.Err("decode public key fail")
		}
		tmp, err = x509.ParsePKIXPublicKey(publish_b.Bytes)
		if err != nil {
			return err
		}
		c.Publish = tmp.(*rsa.PublicKey)
	}
	//
	//
	alipay_b, _ := pem.Decode([]byte(alipay))
	if alipay_b == nil {
		return util.Err("decode alipay key fail")
	}
	tmp, err = x509.ParsePKIXPublicKey(alipay_b.Bytes)
	if err != nil {
		return err
	}
	c.Alipay = tmp.(*rsa.PublicKey)
	return nil
}

func (c *Conf) Md5Sign(data string) string {
	return util.Md5_b([]byte(data + c.MD5))
}

func (c *Conf) ShaSign(data string) (string, error) {
	var hash = sha1.New()
	hash.Write([]byte(data))
	bys, err := rsa.SignPKCS1v15(nil, c.Private, crypto.SHA1, hash.Sum(nil))
	if err == nil {
		return base64.StdEncoding.EncodeToString(bys), nil
	} else {
		return "", err
	}
}

func (c *Conf) Md5Verify(data, sign string) error {
	if c.Md5Sign(data) == sign {
		return nil
	} else {
		return util.Err("md5 verify fail")
	}
}

func (c *Conf) AlipayVerify(data, sign string) error {
	var sigs_b, err = base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return err
	}
	var hash = sha1.New()
	hash.Write([]byte(data))
	return rsa.VerifyPKCS1v15(c.Alipay, crypto.SHA1, hash.Sum(nil), sigs_b)
}

func (c *Conf) Verify(data, sign, sign_type string) error {
	switch sign_type {
	case "MD5":
		return c.Md5Verify(data, sign)
	case "RSA":
		return c.AlipayVerify(data, sign)
	default:
		return util.Err("unkown verify sign type(%v)", sign_type)
	}
}

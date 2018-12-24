package recaptcha

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"testing"

	. "gopkg.in/check.v1"
)

func TestPackage(t *testing.T) { TestingT(t) }

type ReCaptchaSuite struct{}

var _ = Suite(&ReCaptchaSuite{})

type mockSuccessClient struct{}

func (*mockSuccessClient) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
	resp = &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
	}
	resp.Body = ioutil.NopCloser(strings.NewReader(`
	{
		"success": true,
		"challenge_ts": "2018-03-06T03:41:29+00:00",
		"hostname": "test.com"
	}
	`))
	return
}

type mockFailedClient struct{}

func (*mockFailedClient) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
	resp = &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
	}
	resp.Body = ioutil.NopCloser(strings.NewReader(`
	{
		"success": false,
		"challenge_ts": "2018-03-06T03:41:29+00:00",
		"hostname": "test.com",
		"error-codes": ["bad-request"]
	}
	`))
	return
}

type mockInvalidClient struct{}

// bad json body
func (*mockInvalidClient) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
	resp = &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
	}
	resp.Body = ioutil.NopCloser(strings.NewReader(` bogus json `))
	return
}

type mockUnavailableClient struct{}

func (*mockUnavailableClient) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
	resp = &http.Response{
		Status:     "Not Found",
		StatusCode: 404,
	}
	resp.Body = ioutil.NopCloser(nil)
	err = fmt.Errorf("Unable to connect to server")
	return
}

func (s *ReCaptchaSuite) TestNewReCAPTCHA(c *C) {
	captcha, err := NewReCAPTCHA("my secret")
	c.Assert(err, IsNil)
	c.Check(captcha.Secret, Equals, "my secret")
	c.Check(captcha.ReCAPTCHALink, Equals, reCAPTCHALink)

	captcha, err = NewReCAPTCHA("")
	c.Assert(err, NotNil)
}

func (s *ReCaptchaSuite) TestVerifyWithClientIP(c *C) {
	captcha := ReCAPTCHA{
		Client: &mockSuccessClient{},
	}

	success, err := captcha.Verify("mycode", "127.0.0.1")
	c.Assert(err, IsNil)
	c.Check(success, Equals, true)

	captcha.Client = &mockFailedClient{}
	success, err = captcha.Verify("mycode", "127.0.0.1")
	c.Assert(err, IsNil)
	c.Check(success, Equals, false)
}

func (s *ReCaptchaSuite) TestVerifyWithoutClientIP(c *C) {
	captcha := ReCAPTCHA{
		Client: &mockSuccessClient{},
	}

	success, err := captcha.VerifyNoRemoteIP("mycode")
	c.Assert(err, IsNil)
	c.Check(success, Equals, true)

	captcha.Client = &mockFailedClient{}
	success, err = captcha.VerifyNoRemoteIP("mycode")
	c.Assert(err, IsNil)
	c.Check(success, Equals, false)
}

func (s *ReCaptchaSuite) TestConfirm(c *C) {
	// check that an invalid json body errors
	captcha := ReCAPTCHA{
		Client: &mockInvalidClient{},
	}
	body := reCHAPTCHARequest{Secret: "", Response: ""}

	success, err := captcha.confirm(body)
	c.Assert(err, NotNil)
	c.Check(success, Equals, false)

	captcha.Client = &mockUnavailableClient{}
	success, err = captcha.confirm(body)
	c.Assert(err, NotNil)
	c.Check(success, Equals, false)
}

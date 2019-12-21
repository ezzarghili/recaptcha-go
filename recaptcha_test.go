package recaptcha

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	. "gopkg.in/check.v1"
)

func TestPackage(t *testing.T) { TestingT(t) }

type ReCaptchaSuite struct{}

var _ = Suite(&ReCaptchaSuite{})

func (s *ReCaptchaSuite) TestNewReCAPTCHA(c *C) {
	captcha, err := NewReCAPTCHA("my secret", V2, 10*time.Second)
	c.Assert(err, IsNil)
	c.Check(captcha.Secret, Equals, "my secret")
	c.Check(captcha.Version, Equals, V2)
	c.Check(captcha.Timeout, Equals, 10*time.Second)
	c.Check(captcha.ReCAPTCHALink, Equals, reCAPTCHALink)

	captcha, err = NewReCAPTCHA("", V2, 10)
	c.Assert(err, NotNil)
}

type mockInvalidClient struct{}
type mockUnavailableClient struct{}

func (*mockInvalidClient) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
	resp = &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
	}
	resp.Body = ioutil.NopCloser(strings.NewReader(` bogus json `))
	return
}

func (*mockUnavailableClient) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
	resp = &http.Response{
		Status:     "Not Found",
		StatusCode: 404,
	}
	resp.Body = ioutil.NopCloser(nil)
	err = fmt.Errorf("Unable to connect to server")
	return
}

func (s *ReCaptchaSuite) TestConfirm(c *C) {
	captcha := ReCAPTCHA{
		client: &mockInvalidClient{},
	}
	body := reCHAPTCHARequest{Secret: "", Response: ""}

	err := captcha.confirm(body, VerifyOption{})
	c.Assert(err, NotNil)
	c.Check(err, ErrorMatches, "invalid response body json:.*")

	captcha.client = &mockUnavailableClient{}
	err = captcha.confirm(body, VerifyOption{})
	c.Assert(err, NotNil)
	c.Check(err, ErrorMatches, "error posting to recaptcha endpoint:.*")

}

type mockInvalidSolutionClient struct{}

func (*mockInvalidSolutionClient) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
	resp = &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
	}
	resp.Body = ioutil.NopCloser(strings.NewReader(`
	{
		"success": false,
		"challenge_ts": "2018-03-06T03:41:29+00:00",
		"hostname": "test.com"
	}
	`))
	return
}

func (s *ReCaptchaSuite) TestVerifyInvalidSolutionNoRemoteIp(c *C) {
	captcha := ReCAPTCHA{
		client: &mockInvalidSolutionClient{},
	}

	err := captcha.Verify("mycode")
	c.Assert(err, NotNil)
	c.Check(err, ErrorMatches, "invalid challenge solution")
}

type mockSuccessClientNoOptions struct{}
type mockFailedClientNoOptions struct{}

func (*mockSuccessClientNoOptions) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
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
func (*mockFailedClientNoOptions) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
	resp = &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
	}
	resp.Body = ioutil.NopCloser(strings.NewReader(`
	{
		"success": false,
		"challenge_ts": "2018-03-06T03:41:29+00:00",
		"hostname": "test.com",
		"error-codes": ["invalid-input-response","bad-request"]
	}
	`))
	return
}
func (s *ReCaptchaSuite) TestVerifyWithoutOptions(c *C) {
	captcha := ReCAPTCHA{
		client: &mockSuccessClientNoOptions{},
	}

	err := captcha.Verify("mycode")
	c.Assert(err, IsNil)

	captcha.client = &mockFailedClientNoOptions{}
	err = captcha.Verify("mycode")
	c.Assert(err, NotNil)
	c.Check(err, ErrorMatches, "remote error codes:.*")

}

type mockSuccessClientWithRemoteIPOption struct{}
type mockFailClientWithRemoteIPOption struct{}

func (*mockSuccessClientWithRemoteIPOption) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
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
func (*mockFailClientWithRemoteIPOption) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
	resp = &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
	}
	resp.Body = ioutil.NopCloser(strings.NewReader(`
	{
		"success": false,
		"challenge_ts": "2018-03-06T03:41:29+00:00",
		"hostname": "test.com"
	}
	`))
	return
}
func (s *ReCaptchaSuite) TestVerifyWithRemoteIPOption(c *C) {
	captcha := ReCAPTCHA{
		client: &mockSuccessClientWithRemoteIPOption{},
	}

	err := captcha.VerifyWithOptions("mycode", VerifyOption{RemoteIP: "123.123.123.123"})
	c.Assert(err, IsNil)

	captcha.client = &mockFailClientWithRemoteIPOption{}
	err = captcha.VerifyWithOptions("mycode", VerifyOption{RemoteIP: "123.123.123.123"})
	c.Assert(err, NotNil)
	c.Check(err, ErrorMatches, "invalid challenge solution or remote IP")

}

type mockSuccessClientWithHostnameOption struct{}
type mockFailClientWithHostnameOption struct{}

func (*mockSuccessClientWithHostnameOption) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
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
func (*mockFailClientWithHostnameOption) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
	resp = &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
	}
	resp.Body = ioutil.NopCloser(strings.NewReader(`
	{
		"success": true,
		"challenge_ts": "2018-03-06T03:41:29+00:00",
		"hostname": "test2.com"
	}
	`))
	return
}
func (s *ReCaptchaSuite) TestVerifyWithHostnameOption(c *C) {
	captcha := ReCAPTCHA{
		client: &mockSuccessClientWithHostnameOption{},
	}

	err := captcha.VerifyWithOptions("mycode", VerifyOption{Hostname: "test.com"})
	c.Assert(err, IsNil)

	captcha.client = &mockFailClientWithHostnameOption{}
	err = captcha.VerifyWithOptions("mycode", VerifyOption{Hostname: "test.com"})
	c.Assert(err, NotNil)
	c.Check(err, ErrorMatches, "invalid response hostname 'test2.com', while expecting 'test.com'")

}

type mockClockWithinRespenseTime struct{}
type mockClockOverRespenseTime struct{}

func (*mockClockWithinRespenseTime) Since(t time.Time) time.Duration {
	return 1 * time.Second
}

func (*mockClockOverRespenseTime) Since(t time.Time) time.Duration {
	return 8 * time.Second
}

func (s *ReCaptchaSuite) TestVerifyWithResponseOption(c *C) {
	captcha := ReCAPTCHA{
		client:  &mockSuccessClientNoOptions{},
		horloge: &mockClockWithinRespenseTime{},
	}

	err := captcha.VerifyWithOptions("mycode", VerifyOption{ResponseTime: 5 * time.Second})
	c.Assert(err, IsNil)

	captcha.horloge = &mockClockOverRespenseTime{}
	err = captcha.VerifyWithOptions("mycode", VerifyOption{ResponseTime: 5 * time.Second})
	c.Assert(err, NotNil)
	c.Check(err, ErrorMatches, "time spent in resolving challenge '8.000000s', while expecting maximum '5.000000s'")

}

type mockSuccessClientWithApkPackageNameOption struct{}
type mockFailClientWithApkPackageNameOption struct{}

func (*mockSuccessClientWithApkPackageNameOption) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
	resp = &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
	}
	resp.Body = ioutil.NopCloser(strings.NewReader(`
	{
		"success": true,
		"challenge_ts": "2018-03-06T03:41:29+00:00",
		"apk_package_name": "com.test.app"
	}
	`))
	return
}
func (*mockFailClientWithApkPackageNameOption) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
	resp = &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
	}
	resp.Body = ioutil.NopCloser(strings.NewReader(`
	{
		"success": true,
		"challenge_ts": "2018-03-06T03:41:29+00:00",
		"apk_package_name": "com.test.app2"
	}
	`))
	return
}
func (s *ReCaptchaSuite) TestVerifyWithApkPackageNameOption(c *C) {
	captcha := ReCAPTCHA{
		client: &mockSuccessClientWithApkPackageNameOption{},
	}

	err := captcha.VerifyWithOptions("mycode", VerifyOption{ApkPackageName: "com.test.app"})
	c.Assert(err, IsNil)

	captcha.client = &mockFailClientWithApkPackageNameOption{}
	err = captcha.VerifyWithOptions("mycode", VerifyOption{ApkPackageName: "com.test.app"})
	c.Assert(err, NotNil)
	c.Check(err, ErrorMatches, "invalid response ApkPackageName 'com.test.app2', while expecting 'com.test.app'")

}

type mockV3SuccessClientWithActionOption struct{}
type mockV3FailClientWithActionOption struct{}

func (*mockV3SuccessClientWithActionOption) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
	resp = &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
	}
	resp.Body = ioutil.NopCloser(strings.NewReader(`
	{
		"success": true,
		"challenge_ts": "2018-03-06T03:41:29+00:00",
		"action": "homepage",
		"score": 1
	}
	`))
	return
}
func (*mockV3FailClientWithActionOption) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
	resp = &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
	}
	resp.Body = ioutil.NopCloser(strings.NewReader(`
	{
		"success": true,
		"challenge_ts": "2018-03-06T03:41:29+00:00",
		"action": "homepage2",
		"score": 1

	}
	`))
	return
}
func (s *ReCaptchaSuite) TestV3VerifyWithActionOption(c *C) {
	captcha := ReCAPTCHA{
		client:  &mockV3SuccessClientWithActionOption{},
		Version: V3,
	}

	err := captcha.VerifyWithOptions("mycode", VerifyOption{Action: "homepage"})
	c.Assert(err, IsNil)

	captcha.client = &mockV3FailClientWithActionOption{}
	err = captcha.VerifyWithOptions("mycode", VerifyOption{Action: "homepage"})
	c.Assert(err, NotNil)
	c.Check(err, ErrorMatches, "invalid response action 'homepage2', while expecting 'homepage'")

}

type mockV3SuccessClientWithTresholdOption struct{}
type mockV3FailClientWithTresholdOption struct{}

func (*mockV3SuccessClientWithTresholdOption) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
	resp = &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
	}
	resp.Body = ioutil.NopCloser(strings.NewReader(`
	{
		"success": true,
		"challenge_ts": "2018-03-06T03:41:29+00:00",
		"score": 0.8
	}
	`))
	return
}
func (*mockV3FailClientWithTresholdOption) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
	resp = &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
	}
	resp.Body = ioutil.NopCloser(strings.NewReader(`
	{
		"success": true,
		"challenge_ts": "2018-03-06T03:41:29+00:00",
		"score": 0.23
	}
	`))
	return
}
func (s *ReCaptchaSuite) TestV3VerifyWithTresholdOption(c *C) {
	captcha := ReCAPTCHA{
		client:  &mockV3SuccessClientWithTresholdOption{},
		Version: V3,
	}

	err := captcha.VerifyWithOptions("mycode", VerifyOption{Threshold: 0.6})
	c.Assert(err, IsNil)

	captcha.client = &mockV3FailClientWithTresholdOption{}
	err = captcha.VerifyWithOptions("mycode", VerifyOption{Threshold: 0.6})
	c.Assert(err, NotNil)
	c.Check(err, ErrorMatches, "received score '0.230000', while expecting minimum '0.600000'")
	err = captcha.VerifyWithOptions("mycode", VerifyOption{})
	c.Assert(err, NotNil)
	c.Check(err, ErrorMatches, "received score '0.230000', while expecting minimum '0.500000'")
}

type mockV2SuccessClientWithV3IgnoreOptions struct{}

func (*mockV2SuccessClientWithV3IgnoreOptions) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
	resp = &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
	}
	resp.Body = ioutil.NopCloser(strings.NewReader(`
	{
		"success": true,
		"challenge_ts": "2018-03-06T03:41:29+00:00",
	}
	`))
	return
}
func (s *ReCaptchaSuite) TestV2VerifyWithV3IgnoreOptions(c *C) {
	captcha := ReCAPTCHA{
		client:  &mockV3SuccessClientWithTresholdOption{},
		Version: V2,
	}
	err := captcha.VerifyWithOptions("mycode", VerifyOption{Action: "homepage", Threshold: 0.5})
	c.Assert(err, IsNil)
}

/*
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

func (*mockSuccessClientHostnameOption) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
	resp = &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
	}
	resp.Body = ioutil.NopCloser(strings.NewReader(`
	{
		"success": true,
		"challenge_ts": "2018-03-06T03:41:29+00:00",
		"hostname": "valid.com"
	}
	`))
	return
}

func (*mockFailedClientHostnameOption) PostForm(url string, formValues url.Values) (resp *http.Response, err error) {
	resp = &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
	}
	resp.Body = ioutil.NopCloser(strings.NewReader(`
	{
		"success": true,
		"challenge_ts": "2018-03-06T03:41:29+00:00",
		"hostname": "invalid.com"
	}
	`))
	return
}

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

// bad json body

func (s *ReCaptchaSuite) TestNewReCAPTCHA(c *C) {
	captcha, err := NewReCAPTCHA("my secret", V2, 10)
	c.Assert(err, IsNil)
	c.Check(captcha.Secret, Equals, "my secret")
	c.Check(captcha.Version, Equals, V2)
	c.Check(captcha.Timeout, Equals, (uint)(10))
	c.Check(captcha.ReCAPTCHALink, Equals, reCAPTCHALink)

	captcha, err = NewReCAPTCHA("", V2, 10)
	c.Assert(err, NotNil)
}

func (s *ReCaptchaSuite) TestVerifyV2WithoutClientIP(c *C) {
	captcha := ReCAPTCHA{
		client:  &mockSuccessClient{},
		Version: V2,
	}

	success, err := captcha.Verify("mycode")
	c.Assert(err, IsNil)
	c.Check(success, Equals, true)

	captcha.client = &mockFailedClient{}
	success, err = captcha.Verify("mycode")
	c.Assert(err, IsNil)
	c.Check(success, Equals, false)
}

func (s *ReCaptchaSuite) TestV3VerifyWithCHostnameOption(c *C) {
	captcha := ReCAPTCHA{
		client:  &mockSuccessClientHostnameOption{},
		Version: V3,
	}

	success, err := captcha.VerifyWithOptions("mycode", VerifyOption{Hostname: "valid.com"})
	c.Assert(err, IsNil)
	c.Check(success, Equals, true)

	captcha.client = &mockFailedClientHostnameOption{}
	success, err = captcha.VerifyWithOptions("mycode", VerifyOption{Hostname: "valid.com"})
	c.Assert(err, NotNil)
	c.Check(success, Equals, false)
}

/*
func (s *ReCaptchaSuite) TestVerifyWithClientIP(c *C) {
	captcha := ReCAPTCHA{
		client: &mockSuccessClient{},
	}

	success, err := captcha.Verify("mycode", "127.0.0.1")
	c.Assert(err, IsNil)
	c.Check(success, Equals, true)

	captcha.client = &mockFailedClient{}
	success, err = captcha.Verify("mycode", "127.0.0.1")
	c.Assert(err, IsNil)
	c.Check(success, Equals, false)
}

func (s *ReCaptchaSuite) TestConfirm(c *C) {
	// check that an invalid json body errors
	captcha := ReCAPTCHA{
		client: &mockInvalidClient{},
	}
	body := reCHAPTCHARequest{Secret: "", Response: ""}

	success, err := captcha.confirm(body)
	c.Assert(err, NotNil)
	c.Check(success, Equals, false)

	captcha.client = &mockUnavailableClient{}
	success, err = captcha.confirm(body)
	c.Assert(err, NotNil)
	c.Check(success, Equals, false)
}
*/

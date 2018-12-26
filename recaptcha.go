package recaptcha

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

const reCAPTCHALink = "https://www.google.com/recaptcha/api/siteverify"

// VERSION the recaptcha api version
type VERSION int8

const (
	// V2 recaptcha api v2
	V2 VERSION = iota
	// V3 recaptcha api v3, more details can be found here : https://developers.google.com/recaptcha/docs/v3
	V3
	DEFAULT_TRESHOLD float32 = 0.5
)

type reCHAPTCHARequest struct {
	Secret   string `json:"secret"`
	Response string `json:"response"`
	RemoteIP string `json:"remoteip,omitempty"`
}

type reCHAPTCHAResponse struct {
	Success        bool      `json:"success"`
	ChallengeTS    time.Time `json:"challenge_ts"`
	Hostname       string    `json:"hostname,omitempty"`
	ApkPackageName string    `json:"apk_package_name,omitempty"`
	Action         string    `json:"action,omitempty"`
	Score          float32   `json:"score,omitempty"`
	ErrorCodes     []string  `json:"error-codes,omitempty"`
}

// custom client so we can mock in tests
type netClient interface {
	PostForm(url string, formValues url.Values) (resp *http.Response, err error)
}

type clock interface {
	Since(t time.Time) time.Duration
}

type realClock struct {
}

func (realClock) Since(t time.Time) time.Duration {
	return time.Since(t)
}

// ReCAPTCHA recpatcha holder struct, make adding mocking code simpler
type ReCAPTCHA struct {
	Client        netClient
	Secret        string
	ReCAPTCHALink string
	Version       VERSION
	Timeout       uint
	horloge       clock
}

// NewReCAPTCHA Create new ReCAPTCHA with the v2 reCAPTCHA secret optained from https://www.google.com/recaptcha/admin
// or  https://www.google.com/recaptcha/admin
func NewReCAPTCHA(ReCAPTCHASecret string, version VERSION, timeout uint) (ReCAPTCHA, error) {
	if ReCAPTCHASecret == "" {
		return ReCAPTCHA{}, fmt.Errorf("recaptcha secret cannot be blank")
	}
	return ReCAPTCHA{
		Client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
		horloge:       &realClock{},
		Secret:        ReCAPTCHASecret,
		ReCAPTCHALink: reCAPTCHALink,
		Timeout:       timeout,
		Version:       version,
	}, nil
}

// Verify returns (true, nil) if  no error the client answered the challenge correctly and have correct remoteIP
func (r *ReCAPTCHA) Verify(challengeResponse string) error {
	body := reCHAPTCHARequest{Secret: r.Secret, Response: challengeResponse}
	return r.confirm(body, VerifyOption{})
}

// VerifyOption verification options expected for the challenge
type VerifyOption struct {
	Treshold       float32 // ignored in v2 recaptcha
	Action         string  // ignored in v2 recaptcha
	Hostname       string
	ApkPackageName string
	ResponseTime   float64
	RemoteIP       string
}

// VerifyWithOptions returns (true, nil) if  no error the client answered the challenge correctly and have correct remoteIP
func (r *ReCAPTCHA) VerifyWithOptions(challengeResponse string, options VerifyOption) error {
	var body reCHAPTCHARequest
	if options.RemoteIP == "" {
		body = reCHAPTCHARequest{Secret: r.Secret, Response: challengeResponse}
	} else {
		body = reCHAPTCHARequest{Secret: r.Secret, Response: challengeResponse, RemoteIP: options.RemoteIP}
	}
	return r.confirm(body, options)
}

func (r *ReCAPTCHA) confirm(recaptcha reCHAPTCHARequest, options VerifyOption) (Err error) {
	Err = nil
	var formValues url.Values
	if recaptcha.RemoteIP != "" {
		formValues = url.Values{"secret": {recaptcha.Secret}, "remoteip": {recaptcha.RemoteIP}, "response": {recaptcha.Response}}
	} else {
		formValues = url.Values{"secret": {recaptcha.Secret}, "response": {recaptcha.Response}}
	}
	response, err := r.Client.PostForm(r.ReCAPTCHALink, formValues)
	if err != nil {
		Err = fmt.Errorf("error posting to recaptcha endpoint: '%s'", err)
		return
	}
	defer response.Body.Close()
	resultBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		Err = fmt.Errorf("couldn't read response body: '%s'", err)
		return
	}
	var result reCHAPTCHAResponse
	err = json.Unmarshal(resultBody, &result)
	if err != nil {
		Err = fmt.Errorf("invalid response body json: '%s'", err)
		return
	}

	if options.Hostname != "" && options.Hostname != result.Hostname {
		Err = fmt.Errorf("invalid response hostname '%s', while expecting '%s'", result.Hostname, options.Hostname)
		return
	}

	if options.ApkPackageName != "" && options.ApkPackageName != result.ApkPackageName {
		Err = fmt.Errorf("invalid response ApkPackageName '%s', while expecting '%s'", result.ApkPackageName, options.ApkPackageName)
		return
	}

	if options.ResponseTime != 0 {
		duration := r.horloge.Since(result.ChallengeTS).Seconds()
		if options.ResponseTime < duration {
			Err = fmt.Errorf("time spent in resolving challenge '%f', while expecting maximum '%f'", duration, options.ResponseTime)
			return
		}
	}
	if r.Version == V3 {
		if options.Action != "" && options.Action != result.Action {
			Err = fmt.Errorf("invalid response action '%s', while expecting '%s'", result.Action, options.Action)
			return
		}
		if options.Treshold != 0 && options.Treshold >= result.Score {
			Err = fmt.Errorf("received score '%f', while expecting minimum '%f'", result.Score, options.Treshold)
			return
		}
		if options.Treshold == 0 && DEFAULT_TRESHOLD >= result.Score {
			Err = fmt.Errorf("received score '%f', while expecting minimum '%f'", result.Score, DEFAULT_TRESHOLD)
			return
		}
	}
	if result.ErrorCodes != nil {
		Err = fmt.Errorf("remote error codes: %v", result.ErrorCodes)
		return
	}
	if !result.Success && recaptcha.RemoteIP != "" {
		Err = fmt.Errorf("invalid challenge solution or remote IP")
	} else if !result.Success {
		Err = fmt.Errorf("invalid challenge solution")
	}
	return
}

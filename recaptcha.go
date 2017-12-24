package recaptcha

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

var recaptchaSecret string

const reCAPTCHALink = "https://www.google.com/recaptcha/api/siteverify"

type reCHAPTCHRequest struct {
	Secret   string `json:"secret"`
	Response string `json:"response"`
	RemoteIP string `json:"remoteip,omitempty"`
}

type reCHAPTCHResponse struct {
	Success     bool      `json:"success"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes,omitempty"`
}

// Init initialize with the reCAPTCHA secret optained from https://www.google.com/recaptcha/admin
func Init(ReCAPTCHASecret string) {
	recaptchaSecret = ReCAPTCHASecret
}

// Verify returns (true, nil) if  no error the client answered the challenge correctly and have correct remoteIP
func Verify(challenResponse string, remoteIP string) (bool, error) {
	body := reCHAPTCHRequest{Secret: recaptchaSecret, Response: challenResponse, RemoteIP: remoteIP}
	return confirm(body)
}

// VerifyNoRemoteIP returns (true, nil) if no error and the client answered the challenge correctly
func VerifyNoRemoteIP(challenResponse string) (bool, error) {
	body := reCHAPTCHRequest{Secret: recaptchaSecret, Response: challenResponse}
	return confirm(body)
}

func confirm(recaptach reCHAPTCHRequest) (Ok bool, Err error) {
	Ok, Err = false, nil
	if recaptach.Secret == "" {
		Err = fmt.Errorf("recaptcha secret has not been set, please set recaptcha.Init(secret) before calling verification functions")
		return
	}
	// Go http client does not set a default timeout for request, so we need
	// to set one for worse cases when the server hang, we need to make this available in the API
	// to make it possible this library's users to change it, for now a 10s timeout seems resonable
	netClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	jsonValue, _ := json.Marshal(recaptach)
	response, err := netClient.Post(
		reCAPTCHALink, "application/json",
		bytes.NewBuffer(jsonValue),
	)
	if err != nil {
		Err = fmt.Errorf("error posting to recaptcha endpoint: %s", err)
		return
	}
	defer response.Body.Close()
	resultBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		Err = fmt.Errorf("couldn't read response body: %s", err)
		return
	}
	var result reCHAPTCHResponse
	err = json.Unmarshal(resultBody, &result)
	if err != nil {
		Err = fmt.Errorf("invalid response body json: %s", err)
		return
	}
	Ok = result.Success
	return
}

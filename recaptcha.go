package recaptcha

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"
)

const reCAPTCHALink = "https://www.google.com/recaptcha/api/siteverify"

type reCHAPTCHARequest struct {
	Secret   string `json:"secret"`
	Response string `json:"response"`
	RemoteIP string `json:"remoteip,omitempty"`
}

type reCHAPTCHAResponse struct {
	Success     bool      `json:"success"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes,omitempty"`
}

// custom client so we can mock in tests
type netClient interface {
	Post(url string, contentType string, body io.Reader) (resp *http.Response, err error)
}

type ReCAPTCHA struct {
	Client        netClient
	Secret        string
	ReCAPTCHALink string
}

// Create new ReCAPTCHA with the reCAPTCHA secret optained from https://www.google.com/recaptcha/admin
func NewReCAPTCHA(ReCAPTCHASecret string) (ReCAPTCHA, error) {
	if ReCAPTCHASecret == "" {
		return ReCAPTCHA{}, fmt.Errorf("Recaptcha secret cannot be blank.")
	}
	return ReCAPTCHA{
		Client: &http.Client{
			// Go http client does not set a default timeout for request, so we need
			// to set one for worse cases when the server hang, we need to make this available in the API
			// to make it possible this library's users to change it, for now a 10s timeout seems reasonable
			Timeout: 10 * time.Second,
		},
		Secret:        ReCAPTCHASecret,
		ReCAPTCHALink: reCAPTCHALink,
	}, nil
}

// Verify returns (true, nil) if  no error the client answered the challenge correctly and have correct remoteIP
func (r *ReCAPTCHA) Verify(challengeResponse string, remoteIP string) (bool, error) {
	body := reCHAPTCHARequest{Secret: r.Secret, Response: challengeResponse, RemoteIP: remoteIP}
	return r.confirm(body)
}

// VerifyNoRemoteIP returns (true, nil) if no error and the client answered the challenge correctly
func (r *ReCAPTCHA) VerifyNoRemoteIP(challengeResponse string) (bool, error) {
	body := reCHAPTCHARequest{Secret: r.Secret, Response: challengeResponse}
	return r.confirm(body)
}

func (r *ReCAPTCHA) confirm(recaptcha reCHAPTCHARequest) (Ok bool, Err error) {
	Ok, Err = false, nil

	formValue := []byte(`secret=` + recaptcha.Secret + `&response=` + recaptcha.Response)
	response, err := r.Client.Post(
		r.ReCAPTCHALink,
		"application/x-www-form-urlencoded; charset=utf-8",
		bytes.NewBuffer(formValue),
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
	var result reCHAPTCHAResponse
	err = json.Unmarshal(resultBody, &result)
	if err != nil {
		Err = fmt.Errorf("invalid response body json: %s", err)
		return
	}
	Ok = result.Success
	return
}

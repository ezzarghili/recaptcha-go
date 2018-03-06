# recaptcha-go

[![Build Status](https://travis-ci.org/ezzarghili/recaptcha-go.svg?branch=master)](https://travis-ci.org/ezzarghili/recaptcha-go)

Google reCAPTCHA v2 form submittion in golang

## Usage

Install the package in your environment

```bash
go get github.com/ezzarghili/recaptcha-go
```

To use it within your own code

```go
import "github.com/ezzarghili/recaptcha-go"
func main(){
    captcha := recaptcha.NewReCAPTCHA(recaptchaSecret) // get your secret from https://www.google.com/recaptcha/admin
}
```

Now everytime you need to verify a client request use

```go
success, err := captcha.Verify(recaptchaResponse, ClientRemoteIP)
if err !=nil {
    // do something with err (log?)
}
// proceed with success (true|false)
```

or

```go
success, err := captcha.VerifyNoRemoteIP(recaptchaResponse)
if err !=nil {
    // do something with err (log?)
}
// proceed with success (true|false)
```

while `recaptchaResponse` is the form value with name `g-recaptcha-response` sent back by recaptcha server and set for you in the form when user answers the challenge

Both `recaptcha.Verify` and `recaptcha.VerifyNoRemoteIP` return a `bool` and `error` values `(bool, error)`

Use the `error` to check for issues with the secret and connection in the server, and use the `bool` value to verify if the client answered the challenge correctly

### Run Tests
Use the standard go means of running test.

```
go test
```

### Issues with this library

If you have some problems with using this library, bug reports or enhancement please open an issue in the issues tracker.

### License

Let's go with something permitive should we ?

[MIT](https://choosealicense.com/licenses/mit/)

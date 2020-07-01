# recaptcha-go

[![Build Status](https://travis-ci.org/ezzarghili/recaptcha-go.svg?branch=master)](https://travis-ci.org/ezzarghili/recaptcha-go)

Google reCAPTCHA v2 & v3 form submission verification in golang.

## Usage

The API has changed form last version hence the new major version change.  
Old API is still available using the package `gopkg.in/ezzarghili/recaptcha-go.v2` although it does not provide all options available in this version.  
As always install the package in your environment by using a stable API version, see latest version in [releases page](https://github.com/ezzarghili/recaptcha-go/releases).

```bash
go get -u gopkg.in/ezzarghili/recaptcha-go.v4 
```

### recaptcha v2 API

```go
import "gopkg.in/ezzarghili/recaptcha-go.v4"
func main(){
    captcha, _ := recaptcha.NewReCAPTCHA(recaptchaSecret, recaptcha.V2, 10 * time.Second) // for v2 API get your secret from https://www.google.com/recaptcha/admin
}
```

Now everytime you need to verify a V2 API client with no special options request use.

```go
err := captcha.Verify(recaptchaResponse)
if err != nil {
    // do something with err (log?)
    // Example check error codes array if they exist: (err.(*recaptcha.Error)).ErrorCodes
}
// proceed
```

For specific options use the `VerifyWithOptions` method  
Available options for the v2 api are:

```go
  Hostname       string
  ApkPackageName string
  ResponseTime   time.Duration
  RemoteIP       string
```

Other v3 options are ignored and method will return `nil` when succeeded.

```go
err := captcha.VerifyWithOptions(recaptchaResponse, VerifyOption{RemoteIP: "123.123.123.123"})
if err != nil {
    // do something with err (log?)
    // Example check error codes array if they exist: (err.(*recaptcha.Error)).ErrorCodes
}
// proceed
```

### recaptcha v3 API

```go
import "gopkg.in/ezzarghili/recaptcha-go.v4"
func main(){
    captcha, _ := recaptcha.NewReCAPTCHA(recaptchaSecret, recaptcha.V3, 10 * time.Second) // for v3 API use https://g.co/recaptcha/v3 (apperently the same admin UI at the time of writing)
}
```

Now everytime you need to verify a V3 API client with no special options request use.

```go
err := captcha.Verify(recaptchaResponse)
if err != nil {
    // do something with err (log?)
}
// proceed
```
Note that as recaptcha v3 use score for challenge validation, if no threshold option is set the **default** value is `0.5`

For specific options use the `VerifyWithOptions` method.  
Available options for the v3 api are:

```go
   Threshold      float32
   Action         string
   Hostname       string
   ApkPackageName string
   ResponseTime   time.Duration
   RemoteIP       string
```

```go
err := captcha.VerifyWithOptions(recaptchaResponse, VerifyOption{Action: "hompage", Threshold: 0.8})
if err != nil {
    // do something with err (log?)
}
// proceed
```

While `recaptchaResponse` is the form value with name `g-recaptcha-response` sent back by recaptcha server and set for you in the form when a user answers the challenge.

Both `recaptcha.Verify` and `recaptcha.VerifyWithOptions` return a `error` or `nil` if successful.

Use the `error` to check for issues with the secret, connection with the server, options mismatches and incorrect solution.

This version made timeout explcit to make sure users have the possiblity to set the underling http client timeout suitable for their implemetation.

### Run Tests

Use the standard go means of running test.
You can also check examples of usage in the tests.

```bash
go test
```

### Issues with this library

If you have some problems with using this library, bug reports or enhancement please open an issue in the issues tracker.

### License

Let's go with something permitive should we?

[MIT](https://choosealicense.com/licenses/mit/)

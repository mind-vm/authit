module github.com/mind-vm/authit/authhandlers

go 1.25.0

// See sqlbstore/go.mod for why this replace exists (short version: authit is
// a private repo, and this keeps resolution off the network).
replace github.com/mind-vm/authit => ../

require github.com/mind-vm/authit v0.2.0

require (
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/pquerna/otp v1.5.0 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

module github.com/mind-vm/authit/authitctl

go 1.25.0

require (
	github.com/jackc/pgx/v5 v5.10.0
	github.com/mind-vm/authit v0.3.0
	github.com/mind-vm/authit/sqlbstore v0.0.0
	github.com/mind-vm/sqlb v0.20.0
	golang.org/x/term v0.45.0
)

require (
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/pquerna/otp v1.5.0 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)

replace (
	github.com/mind-vm/authit => ../
	github.com/mind-vm/authit/sqlbstore => ../sqlbstore
)

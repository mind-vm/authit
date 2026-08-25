module github.com/mind-vm/authit/sqlbstore

go 1.25.0

// This replace resolves github.com/mind-vm/authit from the working tree
// instead of the network, and it stays permanently -- not just until
// v0.2.0 is tagged -- because github.com/mind-vm/authit is a PRIVATE
// repository. Without it, resolution goes over the network and needs
// GOPRIVATE plus GitHub credentials (see "Access and installation" in the
// README). With it, the workspace resolves everything from the working
// tree and this module cannot be consumed outside that workspace. Drop it
// only for a consumer that has private-module auth configured.
replace github.com/mind-vm/authit => ../

require (
	github.com/jackc/pgx/v5 v5.10.0
	github.com/mind-vm/authit v0.2.0
	github.com/mind-vm/sqlb v0.18.0
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
	golang.org/x/text v0.41.0 // indirect
)

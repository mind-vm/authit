module github.com/jryannel/authit/sqlbstore

go 1.25.0

// v0.1.0 is tagged and pushed, so this replace is no longer what makes the
// require below resolve -- but it stays, because github.com/jryannel/authit
// is a PRIVATE repository. Without it, resolution goes over the network and
// needs GOPRIVATE plus GitHub credentials (see "Access and installation" in
// the README). With it, the workspace resolves everything from the working
// tree and this module cannot be consumed outside that workspace. Drop it
// only for a consumer that has private-module auth configured.
replace github.com/jryannel/authit => ../

require (
	github.com/jackc/pgx/v5 v5.10.0
	github.com/jryannel/authit v0.1.0
	github.com/jryannel/sqlb v0.15.1
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

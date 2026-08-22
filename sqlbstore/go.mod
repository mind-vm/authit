module github.com/jryannel/authit/sqlbstore

go 1.25.0

// TRANSITIONAL. The require below names the version this module intends to
// consume; this replace is what makes it resolve before that tag exists.
// Remove this line once github.com/jryannel/authit v0.1.0 is tagged and
// pushed -- go.work is what keeps local development working after it goes,
// and while it is here, this module cannot be consumed outside a workspace.
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

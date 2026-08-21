module github.com/jryannel/authit/sqlbstore

go 1.25.0

replace github.com/jryannel/authit => ../

require (
	github.com/jackc/pgx/v5 v5.10.0
	github.com/jryannel/authit v0.0.0-00010101000000-000000000000
	github.com/jryannel/sqlb v0.15.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/text v0.37.0 // indirect
)

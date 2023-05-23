module github.com/gopsql/bcrypt/tests

go 1.16

replace github.com/gopsql/bcrypt => ../

require (
	github.com/gopsql/bcrypt v0.0.0
	github.com/gopsql/gopg v1.2.1
	github.com/gopsql/logger v1.0.0
	github.com/gopsql/pq v1.2.1
	github.com/gopsql/psql v1.9.0
)

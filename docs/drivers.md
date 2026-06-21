# Driver Support

goauth supports three database drivers. Postgres is registered automatically.
SQLite and MySQL require a blank import in your application's main package.

## PostgreSQL (default)

No extra import needed.

```go
Database.Driver = goauth.DriverPostgres
```

## SQLite

```
go get modernc.org/sqlite
```

```go
// in your main.go or auth.go:
import _ "modernc.org/sqlite"

Database.Driver = goauth.DriverSQLite
```

## MySQL

```
go get github.com/go-sql-driver/mysql
```

```go
// in your main.go or auth.go:
import _ "github.com/go-sql-driver/mysql"

Database.Driver = goauth.DriverMySQL
```

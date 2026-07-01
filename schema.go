package goauth

import "fmt"

func ErrNoSchema(driver string) error {
	return fmt.Errorf("goauth: unsupported driver %q — valid options: postgres, sqlite, mysql", driver)
}

func GetSchema(driver string) (string, error) {
	s, ok := driverSchemas[driver]
	if !ok {
		return "", ErrNoSchema(driver)
	}
	return s, nil
}

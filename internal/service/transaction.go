package service

import (
	"reflect"

	"github.com/nazimdjebloun/go-auth/port"
)

// requireTxManager rejects incomplete internal wiring before a service can
// handle requests. A missing manager is a programming error, not an optional
// autocommit mode. Check typed nils too: an interface holding a nil pointer is
// non-nil but cannot provide the required transaction boundary.
func requireTxManager(tx port.TxManager) {
	if tx != nil {
		value := reflect.ValueOf(tx)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			if !value.IsNil() {
				return
			}
		default:
			return
		}
	}
	panic("goauth: service requires a non-nil transaction manager")
}

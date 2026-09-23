// Package registry selects password hashers from encoded hash prefixes.
package registry

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/nazimdjebloun/go-auth/hasher/argon2id"
	"github.com/nazimdjebloun/go-auth/port"
	"golang.org/x/crypto/bcrypt"
)

var errUnsupportedHashFormat = errors.New("hasher registry: unsupported password hash format")

// ErrUnsupportedHashFormat reports a stored hash with no registered verifier.
var ErrUnsupportedHashFormat = errUnsupportedHashFormat

// Registry implements port.Hasher by dispatching Compare on the stored
// hash's own identifying prefix — never on whichever hasher is currently
// configured. The prefix is the algorithm identity baked into the stored
// string itself: MCF-style hashes carry it up front ("$2a$" bcrypt,
// "$argon2id$" Argon2id), and Django-style identifiers work the same way
// ("pbkdf2_sha256$" — first field up to its separator). Hash always uses
// current; Compare looks up the entry registered for the stored hash's
// prefix and delegates.
//
// This is what makes switching hashers non-breaking: hashes written under a
// previous hasher stay verifiable after WithPasswordHasher changes current,
// because the registry keeps an entry for every algorithm that may still be
// in the database — built-in bcrypt and Argon2id, plus current itself. A prefix that
// matches no entry fails closed with errUnsupportedHashFormat rather
// than falling back to current: silently trying current against a hash it
// didn't produce would at best burn a KDF round and at worst — with a
// consumer hasher lax about malformed input — verify against garbage.
//
// Build it through goauth.New (WithPasswordHasher / WithBcryptCost); the
// constructor is exported for direct service wiring and tests.
type Registry struct {
	current   port.Hasher
	forVerify map[string]port.Hasher

	currentPrefix     string
	currentParameters string

	// probe is the hash current produced at construction time — a real
	// hash of a fixed plaintext, in current's exact format. authenticate
	// uses it as the dummy comparison on the user-not-found path so that
	// path burns the same algorithm's work as a real password check, not
	// bcrypt's, when a non-bcrypt hasher is configured.
	probe string

	// currentIsBcrypt and currentCost classify current's format from the
	// same probe. needsRehash compares a stored hash's algorithm (and, for
	// bcrypt, cost) against them to decide whether rehash-on-login should
	// upgrade the row.
	currentIsBcrypt bool
	currentCost     int
}

// bcryptVerifyPrefixes are the four minor-version prefixes of the bcrypt
// family. x/crypto/bcrypt always writes "$2a$" but verifies all four, so a
// hash imported from a system that writes "$2b$" (or "$2x$"/"$2y$", produced
// by crypt_blowfish implementations) verifies just as well as one this
// library wrote. All four key the same entry.
func bcryptVerifyPrefixes() []string {
	return []string{"$2a$", "$2b$", "$2x$", "$2y$"}
}

// isBcryptFormat reports whether a hash string carries any bcrypt-family
// prefix.
func isBcryptFormat(hash string) bool {
	for _, p := range bcryptVerifyPrefixes() {
		if strings.HasPrefix(hash, p) {
			return true
		}
	}
	return false
}

// hashFormatPrefix returns the identifying prefix of a hash string — the
// key the registry dispatches on.
//
// It runs to the end of the first "$"-separated field: bcrypt's
// "$2a$12$…" yields "$2a$" (the cost field stays out of the identity),
// Argon2id's "$argon2id$v=19$m=…" yields "$argon2id$", and a Django-style
// "pbkdf2_sha256$150000$…" yields "pbkdf2_sha256$". A string with no field
// separator yields itself — a bare value then simply fails the registry
// lookup, the same fail-closed path as an unknown algorithm.
func hashFormatPrefix(hash string) string {
	if hash == "" {
		return ""
	}
	start := 0
	if hash[0] == '$' {
		start = 1
	}
	next := strings.IndexByte(hash[start:], '$')
	if next < 0 {
		return hash
	}
	return hash[:start+next+1]
}

// HashFormatPrefix returns the identifying prefix used for verifier dispatch.
func HashFormatPrefix(hash string) string {
	return hashFormatPrefix(hash)
}

// hashParameterFingerprint returns the algorithm-and-parameters portion of
// a self-describing hash while dropping its salt and digest. This covers the
// common MCF/PHC shapes used by Argon2id and scrypt as well as Django-style
// PBKDF2 strings. Bcrypt is handled separately through bcrypt.Cost because
// its salt and digest share one field.
func hashParameterFingerprint(hash string) string {
	parts := strings.Split(hash, "$")
	if len(parts) < 4 {
		return ""
	}
	return strings.Join(parts[:len(parts)-2], "$")
}

// New builds the dispatch table. current is used for all new
// hashes and registered for verification under its own prefix, extracted by
// hashing a fixed probe value once — a live hasher object cannot be asked
// its algorithm (port.Hasher is two methods by design), but its output always
// self-identifies, which is the same property dispatch relies on at
// verification time.
//
// legacyForVerify registers additional hashers for algorithms that may still
// be in the database but are no longer current. Argon2id is registered
// directly under its standard prefix without an expensive probe; goauth.New
// additionally passes a default-cost bcrypt hasher. The variadic exists for
// direct wiring that carries other history. A legacy bcrypt entry is
// mandatory: current being non-bcrypt with no bcrypt verifier would lock out
// every pre-migration row, so that combination is a construction error, not a
// silent fail-closed-at-login.
//
// Errors are returned only at construction time, where a bad hasher is
// cheapest to catch: current whose Hash fails, whose output carries no
// identifying prefix (a hash format the registry itself cannot recognize
// cannot be dispatched even against the hasher that produced it), or that
// claims a bcrypt prefix with unparseable cost parameters.
func New(current port.Hasher, legacyForVerify ...port.Hasher) (*Registry, error) {
	if isNilHasher(current) {
		return nil, fmt.Errorf("hasher registry: current hasher is nil")
	}
	const probeInput = "goauth-hasher-registry-probe"
	probe, err := current.Hash(probeInput)
	if err != nil {
		return nil, fmt.Errorf("hasher registry: current hasher failed to hash: %w", err)
	}
	if err := current.Compare(probeInput, probe); err != nil {
		return nil, fmt.Errorf("hasher registry: current hasher cannot verify its own output: %w", err)
	}
	prefix := hashFormatPrefix(probe)
	if prefix == "" || prefix == probe {
		return nil, fmt.Errorf(
			"hasher registry: current hasher output %q has no identifying prefix — "+
				"stored hashes must self-identify their algorithm (MCF-style, e.g. $2a$…, $argon2id$…)",
			probe,
		)
	}

	r := &Registry{
		current: current,
		// Argon2id is a built-in legacy verifier even when bcrypt remains
		// current. Unlike a generic legacy hasher, its standard prefix is
		// known here, so registering it does not need an expensive startup
		// probe. A configured current implementation with the same prefix
		// replaces this entry below.
		forVerify: map[string]port.Hasher{
			"$argon2id$": argon2id.New(argon2id.DefaultOptions()),
		},
		currentPrefix:     prefix,
		currentParameters: hashParameterFingerprint(probe),
		probe:             probe,
	}
	if isBcryptFormat(prefix) {
		// A bcrypt current verifies the whole 2x family itself. The built-in
		// Argon2id verifier is already registered above, so neither built-in
		// legacy algorithm needs another startup probe.
		cost, err := bcrypt.Cost([]byte(probe))
		if err != nil {
			return nil, fmt.Errorf("hasher registry: bcrypt hasher produced a hash with unparseable cost: %w", err)
		}
		r.currentIsBcrypt = true
		r.currentCost = cost
		for _, p := range bcryptVerifyPrefixes() {
			r.forVerify[p] = current
		}
		return r, nil
	}

	// Register legacy entries first so current wins any prefix collision
	// (two argon2id instances, for instance — the newer one is the one
	// configured, and it verifies the same family).
	for _, h := range legacyForVerify {
		if isNilHasher(h) {
			continue
		}
		legacyProbe, lerr := h.Hash(probeInput)
		if lerr != nil {
			return nil, fmt.Errorf("hasher registry: legacy hasher failed to hash: %w", lerr)
		}
		if isBcryptFormat(legacyProbe) {
			// Bcrypt-family legacy: one entry per verify prefix, pointing at
			// this hasher. The first bcrypt-capable legacy wins; a later one
			// is redundant (bcrypt verifies the whole family regardless of
			// its configured cost — Compare reads cost from each stored
			// hash, not from the hasher).
			for _, p := range bcryptVerifyPrefixes() {
				if _, taken := r.forVerify[p]; !taken {
					r.forVerify[p] = h
				}
			}
			continue
		}
		legacyPrefix := hashFormatPrefix(legacyProbe)
		if legacyPrefix == "" || legacyPrefix == legacyProbe {
			return nil, fmt.Errorf(
				"hasher registry: legacy hasher output %q has no identifying prefix",
				legacyProbe,
			)
		}
		r.forVerify[legacyPrefix] = h
	}

	// current is a different algorithm: register it under its own prefix,
	// and require a bcrypt verifier for the rows go-auth wrote before any
	// WithPasswordHasher call.
	if _, hasBcrypt := r.forVerify["$2a$"]; !hasBcrypt {
		return nil, fmt.Errorf(
			"hasher registry: current hasher is not bcrypt and no bcrypt legacy hasher was provided — " +
				"existing bcrypt password rows would have no verifier",
		)
	}
	r.forVerify[prefix] = current
	return r, nil
}

func isNilHasher(h port.Hasher) bool {
	if h == nil {
		return true
	}
	v := reflect.ValueOf(h)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// Hash always uses current — new and re-hashed passwords are written under
// the configured algorithm, never under whatever produced the row being
// replaced.
func (r *Registry) Hash(password string) (string, error) {
	return r.current.Hash(password)
}

// Compare dispatches on the stored hash's identifying prefix. An unknown or
// corrupted prefix — including an empty string and a bare value with no field
// separator — fails closed with errUnsupportedHashFormat: no fallback
// to current, no panic, no guessing. This is the fail-closed contract: a
// hash this deployment cannot recognize cannot be safely verified by
// anything.
func (r *Registry) Compare(password, stored string) error {
	h, ok := r.forVerify[hashFormatPrefix(stored)]
	if !ok || h == nil {
		return errUnsupportedHashFormat
	}
	return h.Compare(password, stored)
}

// DummyHash returns a hash in current's exact format for the user-not-found
// path's timing-equalizing comparison — see authenticate. It is a real hash
// of a fixed probe plaintext, so comparing against it runs the same
// algorithm and cost as comparing a real password, and its result is always
// discarded.
func (r *Registry) DummyHash() string {
	return r.probe
}

// BurnDummy performs real password-KDF work for a row that cannot be checked
// because its pepper version is unavailable. A well-formed known hash runs
// with its own embedded parameters. If the format is unknown or malformed,
// the current probe guarantees one full comparison at the current cost.
func (r *Registry) BurnDummy(stored string) {
	const candidate = "goauth-unsupported-pepper-version-dummy"
	err := r.Compare(candidate, stored)
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) || errors.Is(err, argon2id.ErrPasswordMismatch) {
		return
	}
	_ = r.Compare(candidate, r.probe)
}

// NeedsRehash reports whether a just-verified stored hash is due for an
// upgrade to current: a different algorithm than current, or the same
// bcrypt-family algorithm at a different cost. It inspects only the stored
// string and the probe facts — no hashing runs — so it is cheap enough to
// call on every successful login. Same algorithm and (for bcrypt) same cost
// report false, so the steady state costs nothing.
//
// The bcrypt cost check is what makes WithBcryptCost(14) upgrade a cost-12
// database row by row as its owners log in — no batch migration job, no
// forced reset. Minor-version differences within the bcrypt family ("$2b$"
// stored, current writes "$2a$") deliberately do not trigger a rehash: the
// family verifies interchangeably, so re-hashing would buy nothing.
func (r *Registry) NeedsRehash(stored string) bool {
	storedPrefix := hashFormatPrefix(stored)
	if _, ok := r.forVerify[storedPrefix]; !ok {
		// Unverifiable format — Compare fails before this matters. Report
		// true so a caller that somehow reaches here still upgrades.
		return true
	}
	if storedPrefix != r.currentPrefix && (!r.currentIsBcrypt || !isBcryptFormat(stored)) {
		// A different registered prefix was verified by a legacy hasher.
		return true
	}
	if !r.currentIsBcrypt {
		// PHC/MCF-style hashes place algorithm parameters before their last
		// two fields (salt and digest). Comparing that stable portion catches
		// Argon2id/scrypt/PBKDF2 parameter changes without expanding
		// port.Hasher with algorithm-specific methods. If a custom format
		// exposes no separable parameter fields, its prefix remains the only
		// identity available through the Hasher contract.
		storedParameters := hashParameterFingerprint(stored)
		return r.currentParameters != "" && storedParameters != r.currentParameters
	}
	storedCost, err := bcrypt.Cost([]byte(stored))
	if err != nil {
		// Prefix matched but the cost field is damaged — upgrading rewrites
		// the row cleanly.
		return true
	}
	// Same bcrypt family; upgrade only when the cost differs. That's what
	// makes WithBcryptCost(14) lift a cost-12 database row by row as its
	// owners log in — no batch migration, no forced reset. Minor-version
	// differences within the family ("$2b$" stored, current writes "$2a$")
	// deliberately don't trigger a rehash: the family verifies
	// interchangeably, so re-hashing would buy nothing.
	return storedCost != r.currentCost
}

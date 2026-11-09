package goauth

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// ConfigIssueCode classifies a configuration problem independently of its prose.
type ConfigIssueCode string

// ConfigRequired and the following values classify configuration problems.
// Applications should handle unknown future codes as validation failures and
// display the issue's Message.
const (
	ConfigRequired    ConfigIssueCode = "required"
	ConfigInvalid     ConfigIssueCode = "invalid_value"
	ConfigRange       ConfigIssueCode = "out_of_range"
	ConfigConflict    ConfigIssueCode = "conflict"
	ConfigDependency  ConfigIssueCode = "dependency_required"
	ConfigInsecure    ConfigIssueCode = "insecure"
	ConfigUnsupported ConfigIssueCode = "unsupported"
	ConfigDuplicate   ConfigIssueCode = "duplicate"
)

// ConfigIssue identifies a field using exported configuration vocabulary,
// such as Browser.AllowedOrigins[0] or PasswordHashing.Pepper.Keys[2]. Standalone
// options use their name without With (Secret, Mailer, Providers, RateLimit).
// A group path identifies a constraint involving several fields. Submitted
// strings and credentials are omitted; collection indices are safe metadata.
// Message is for people and is not a stable machine-readable contract.
type ConfigIssue struct {
	Field   string          `json:"field"`
	Code    ConfigIssueCode `json:"code"`
	Message string          `json:"message"`
}

func (e *ConfigIssue) Error() string { return e.Field + ": " + e.Message }

// ConfigError reports all configuration issues, sorted by Field, Code and
// Message. NewConfig, Config.Describe and New's static validation return it;
// connection, schema and custom integration startup failures remain separate.
// The error owns its Issues slice. Wrapping with %w preserves errors.As access
// to this collection and to its first matching *ConfigIssue.
type ConfigError struct {
	Issues []ConfigIssue `json:"issues"`
}

func (e *ConfigError) Error() string {
	messages := make([]string, len(e.Issues))
	for i := range e.Issues {
		messages[i] = e.Issues[i].Error()
	}
	return strings.Join(messages, "\n")
}

// Unwrap lets standard error inspection traverse the individual issues.
func (e *ConfigError) Unwrap() []error {
	errs := make([]error, len(e.Issues))
	for i := range e.Issues {
		errs[i] = &e.Issues[i]
	}
	return errs
}

func configIssue(field string, code ConfigIssueCode, message string, args ...any) *ConfigIssue {
	if len(args) > 0 {
		message = fmt.Sprintf(message, args...)
	}
	return &ConfigIssue{Field: field, Code: code, Message: message}
}

func joinConfigIssues(errs ...error) error {
	var issues []ConfigIssue
	for _, err := range errs {
		if err == nil {
			continue
		}
		var group *ConfigError
		var issue *ConfigIssue
		switch {
		case errors.As(err, &group):
			issues = append(issues, group.Issues...)
		case errors.As(err, &issue):
			issues = append(issues, *issue)
		default:
			// Validators must assign a public path at the source. Never expose
			// unclassified integration error text as configuration diagnostics.
			issues = append(issues, ConfigIssue{
				Field: "Config", Code: ConfigInvalid, Message: "invalid configuration",
			})
		}
	}
	if len(issues) == 0 {
		return nil
	}
	slices.SortStableFunc(issues, func(a, b ConfigIssue) int {
		if n := strings.Compare(a.Field, b.Field); n != 0 {
			return n
		}
		if n := strings.Compare(string(a.Code), string(b.Code)); n != 0 {
			return n
		}
		return strings.Compare(a.Message, b.Message)
	})
	return &ConfigError{Issues: issues}
}

func nilConfigIntegration(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

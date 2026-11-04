package emailtemplate

import (
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/port"
)

func TestEmailChangeDestinationIsNotDisplayText(t *testing.T) {
	provider, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{"current", "new", "RENAMED_INTERNAL_DESTINATION"} {
		message, err := provider.Render(port.EmailChangeData{AppName: "App", Code: "ABCDEFGH", NewEmail: "new@example.com", Destination: destination, ExpiresIn: 10 * time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		for _, body := range []string{message.HTML, message.Text} {
			if !strings.Contains(body, "email address that received this message") || !strings.Contains(body, "ABCDEFGH") || strings.Contains(body, "your "+destination+" email address") || strings.Contains(body, "RENAMED_INTERNAL_DESTINATION") {
				t.Fatal("template used a routing identifier as display text")
			}
		}
	}
}

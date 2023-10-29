package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	headers := make(http.Header)

	t.Run("NoAuthorizationHeader", func(t *testing.T) {
		_, err := GetAPIKey(headers)
		if err != ErrNoAuthHeaderIncluded {
			t.Errorf("expected error %v; got %v", ErrNoAuthHeaderIncluded, err)
		}
	})

	t.Run("MalformedAuthorizationHeader", func(t *testing.T) {
		headers.Set("Authorization", "InvalidFormat")
		_, err := GetAPIKey(headers)
		if err == nil {
			t.Error("expected error; got nil")
		}
	})

	t.Run("ValidAuthorizationHeader", func(t *testing.T) {
		apiKey := "testAPIKey"
		headers.Set("Authorization", "ApiKey "+apiKey)
		key, err := GetAPIKey(headers)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if key != apiKey {
			t.Errorf("expected key %s; got %s", apiKey, key)
		}
	})
}

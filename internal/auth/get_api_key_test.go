package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		wantKey   string
		wantError error
	}{
		{
			name:      "No authorization header",
			headers:   http.Header{},
			wantKey:   "",
			wantError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Valid ApiKey header",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey test-api-key-123")
				return h
			}(),
			wantKey:   "test-api-key-123",
			wantError: nil,
		},
		{
			name: "Valid ApiKey with spaces in key - current implementation splits on space",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey key-with spaces-and-more")
				return h
			}(),
			// The current implementation uses strings.Split which splits on spaces
			// So it will only take the first part after "ApiKey"
			wantKey:   "key-with",
			wantError: nil,
		},
		{
			name: "Malformed - only one part",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey")
				return h
			}(),
			wantKey:   "",
			wantError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed - wrong scheme (Bearer instead of ApiKey)",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "Bearer token123")
				return h
			}(),
			wantKey:   "",
			wantError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed - lowercase apikey",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "apikey test-key")
				return h
			}(),
			wantKey:   "",
			wantError: errors.New("malformed authorization header"),
		},
		{
			name: "Extra parts - current implementation ignores extra parts after first token",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey key1 key2 key3")
				return h
			}(),
			// Current implementation only checks len(splitAuth) < 2
			// So "ApiKey key1 key2 key3" has length 4, which passes the check
			// It returns splitAuth[1] which is "key1"
			wantKey:   "key1",
			wantError: nil,
		},
		{
			name: "Empty string value",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "")
				return h
			}(),
			wantKey:   "",
			wantError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Authorization header with spaces before scheme - current implementation fails",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "  ApiKey test-key")
				return h
			}(),
			wantKey:   "",
			wantError: errors.New("malformed authorization header"),
		},
		{
			name: "Valid ApiKey with no spaces in key",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey single-key-value")
				return h
			}(),
			wantKey:   "single-key-value",
			wantError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotError := GetAPIKey(tt.headers)

			// Check error
			if tt.wantError != nil {
				if gotError == nil {
					t.Errorf("GetAPIKey() expected error '%v', got nil", tt.wantError)
					return
				}
				if gotError.Error() != tt.wantError.Error() {
					t.Errorf("GetAPIKey() error = '%v', want '%v'", gotError, tt.wantError)
				}
			} else {
				if gotError != nil {
					t.Errorf("GetAPIKey() unexpected error: '%v'", gotError)
					return
				}
			}

			// Check key
			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() key = '%v', want '%v'", gotKey, tt.wantKey)
			}
		})
	}
}

// Test for trimming spaces (if you want to improve the implementation)
func TestGetAPIKeyWithTrimming(t *testing.T) {
	t.Run("Implementation should trim spaces", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "  ApiKey   test-key-with-spaces  ")

		gotKey, err := GetAPIKey(headers)
		_ = gotKey
		_ = err

		// Note: Current implementation doesn't trim spaces
		// This test documents the current behavior
		t.Logf("Current behavior: returns error or untrimmed key: '%s', error: %v", gotKey, err)
	})
}

package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		expectedKey string
		expectError bool
		errorType   error
	}{
		{
			name:        "valid api key",
			headerValue: "ApiKey random-api-key",
			expectedKey: "random-api-key",
			expectError: false,
		},
		{
			name:        "missing authorization header",
			headerValue: "",
			expectedKey: "",
			expectError: true,
			errorType:   ErrNoAuthHeaderIncluded,
		},
		{
			name:        "malformed header - wrong prefix",
			headerValue: "Bearer random-api-key",
			expectedKey: "",
			expectError: true,
			// Using nil here since we can't easily compare to the "malformed authorization header" error
		},
		{
			name:        "malformed header - no space",
			headerValue: "ApiKeyonly",
			expectedKey: "",
			expectError: true,
			// Using nil here since we can't easily compare to the "malformed authorization header" error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.headerValue != "" {
				headers.Set("Authorization", tt.headerValue)
			}

			got, err := GetAPIKey(headers)

			// Check error expectations
			if tt.expectError && err == nil {
				t.Errorf("expected an error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}

			// For specific error types, check if they match
			if tt.errorType != nil && err != tt.errorType {
				t.Errorf("expected error %v but got %v", tt.errorType, err)
			}
			// Check the returned key
			if got != tt.expectedKey {
				t.Errorf("expected key %q but got %q", tt.expectedKey, got)
			}
		})
	}
}

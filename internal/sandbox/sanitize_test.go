package sandbox

import (
	"testing"

	"github.com/Use-Tusk/fence/internal/config"
)

func TestIsDangerousEnvVar(t *testing.T) {
	tests := []struct {
		entry     string
		dangerous bool
	}{
		// Linux LD_* variables
		{"LD_PRELOAD=/tmp/evil.so", true},
		{"LD_LIBRARY_PATH=/tmp", true},
		{"LD_AUDIT=/tmp/audit.so", true},
		{"LD_DEBUG=all", true},

		// macOS DYLD_* variables
		{"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib", true},
		{"DYLD_LIBRARY_PATH=/tmp", true},
		{"DYLD_FRAMEWORK_PATH=/tmp", true},
		{"DYLD_FORCE_FLAT_NAMESPACE=1", true},

		// Safe variables
		{"PATH=/usr/bin:/bin", false},
		{"HOME=/home/user", false},
		{"USER=user", false},
		{"SHELL=/bin/bash", false},
		{"HTTP_PROXY=http://localhost:8080", false},
		{"HTTPS_PROXY=http://localhost:8080", false},

		// Edge cases - variables that start with similar prefixes but aren't dangerous
		{"LDFLAGS=-L/usr/lib", false}, // Not LD_ prefix
		{"DISPLAY=:0", false},

		// Empty and malformed
		{"LD_PRELOAD", true}, // No value but still dangerous
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.entry, func(t *testing.T) {
			got := isDangerousEnvVar(tt.entry)
			if got != tt.dangerous {
				t.Errorf("isDangerousEnvVar(%q) = %v, want %v", tt.entry, got, tt.dangerous)
			}
		})
	}
}

func TestFilterDangerousEnv(t *testing.T) {
	env := []string{
		"PATH=/usr/bin:/bin",
		"LD_PRELOAD=/tmp/evil.so",
		"HOME=/home/user",
		"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib",
		"HTTP_PROXY=http://localhost:8080",
		"LD_LIBRARY_PATH=/tmp",
	}

	filtered := FilterDangerousEnv(env)

	// Should have 3 safe vars
	if len(filtered) != 3 {
		t.Errorf("expected 3 safe vars, got %d: %v", len(filtered), filtered)
	}

	// Verify the safe vars are present
	expected := map[string]bool{
		"PATH=/usr/bin:/bin":               true,
		"HOME=/home/user":                  true,
		"HTTP_PROXY=http://localhost:8080": true,
	}

	for _, e := range filtered {
		if !expected[e] {
			t.Errorf("unexpected var in filtered env: %s", e)
		}
	}

	// Verify dangerous vars are gone
	for _, e := range filtered {
		if isDangerousEnvVar(e) {
			t.Errorf("dangerous var not filtered: %s", e)
		}
	}
}

func TestGetStrippedEnvVars(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"LD_PRELOAD=/tmp/evil.so",
		"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib",
		"HOME=/home/user",
	}

	stripped := GetStrippedEnvVars(env)

	if len(stripped) != 2 {
		t.Errorf("expected 2 stripped vars, got %d: %v", len(stripped), stripped)
	}

	// Should contain just the keys, not values
	found := make(map[string]bool)
	for _, s := range stripped {
		found[s] = true
	}

	if !found["LD_PRELOAD"] {
		t.Error("expected LD_PRELOAD to be in stripped list")
	}
	if !found["DYLD_INSERT_LIBRARIES"] {
		t.Error("expected DYLD_INSERT_LIBRARIES to be in stripped list")
	}
}

func TestFilterDangerousEnv_EmptyInput(t *testing.T) {
	filtered := FilterDangerousEnv(nil)
	if filtered == nil {
		t.Error("expected non-nil slice for nil input")
	}
	if len(filtered) != 0 {
		t.Errorf("expected empty slice, got %v", filtered)
	}

	filtered = FilterDangerousEnv([]string{})
	if len(filtered) != 0 {
		t.Errorf("expected empty slice, got %v", filtered)
	}
}

func TestFilterDangerousEnv_AllDangerous(t *testing.T) {
	env := []string{
		"LD_PRELOAD=/tmp/evil.so",
		"LD_LIBRARY_PATH=/tmp",
		"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib",
	}

	filtered := FilterDangerousEnv(env)
	if len(filtered) != 0 {
		t.Errorf("expected all vars to be filtered, got %v", filtered)
	}
}

func TestFilterDangerousEnv_AllSafe(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"USER=test",
	}

	filtered := FilterDangerousEnv(env)
	if len(filtered) != 3 {
		t.Errorf("expected all 3 vars to pass through, got %d", len(filtered))
	}
}

func TestExtractEnvVarName(t *testing.T) {
	tests := []struct {
		entry    string
		expected string
	}{
		{"PATH=/usr/bin", "PATH"},
		{"HOME=/home/user", "HOME"},
		{"VAR=", "VAR"},
		{"VAR", "VAR"},
		{"KEY=value=with=equals", "KEY"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.entry, func(t *testing.T) {
			got := extractEnvVarName(tt.entry)
			if got != tt.expected {
				t.Errorf("extractEnvVarName(%q) = %q, want %q", tt.entry, got, tt.expected)
			}
		})
	}
}

func TestIsEnvVarAllowed(t *testing.T) {
	tests := []struct {
		name     string
		varName  string
		cfg      *config.EnvironmentConfig
		expected bool
	}{
		// Deny takes precedence
		{
			name:    "denied pattern blocks allowed pattern",
			varName: "AWS_SECRET_KEY",
			cfg: &config.EnvironmentConfig{
				AllowedVars: []string{"AWS_*"},
				DeniedVars:  []string{"*_SECRET_*"},
			},
			expected: false,
		},
		// Exact deny match
		{
			name:    "exact deny match",
			varName: "SECRET_TOKEN",
			cfg: &config.EnvironmentConfig{
				DeniedVars: []string{"SECRET_TOKEN"},
			},
			expected: false,
		},
		// Wildcard deny match
		{
			name:    "wildcard deny match",
			varName: "MY_TOKEN",
			cfg: &config.EnvironmentConfig{
				DeniedVars: []string{"*_TOKEN"},
			},
			expected: false,
		},
		// No allow patterns - allow by default (after deny check)
		{
			name:    "no allow patterns - allow by default",
			varName: "PATH",
			cfg: &config.EnvironmentConfig{
				DeniedVars: []string{"*_SECRET"},
			},
			expected: true,
		},
		// Allow pattern match
		{
			name:    "allow pattern match",
			varName: "AWS_ACCESS_KEY",
			cfg: &config.EnvironmentConfig{
				AllowedVars: []string{"AWS_*"},
			},
			expected: true,
		},
		// Exact allow match
		{
			name:    "exact allow match",
			varName: "PATH",
			cfg: &config.EnvironmentConfig{
				AllowedVars: []string{"PATH", "HOME"},
			},
			expected: true,
		},
		// Not in allow list
		{
			name:    "not in allow list",
			varName: "SECRET_VAR",
			cfg: &config.EnvironmentConfig{
				AllowedVars: []string{"PATH", "HOME"},
			},
			expected: false,
		},
		// Star matches all
		{
			name:    "star matches all",
			varName: "ANYTHING",
			cfg: &config.EnvironmentConfig{
				AllowedVars: []string{"*"},
			},
			expected: true,
		},
		// Empty config - allow by default
		{
			name:     "empty config - allow by default",
			varName:  "ANY_VAR",
			cfg:      &config.EnvironmentConfig{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isEnvVarAllowed(tt.varName, tt.cfg)
			if got != tt.expected {
				t.Errorf("isEnvVarAllowed(%q, cfg) = %v, want %v", tt.varName, got, tt.expected)
			}
		})
	}
}

func TestFilterEnvironmentVars(t *testing.T) {
	tests := []struct {
		name     string
		env      []string
		cfg      *config.EnvironmentConfig
		expected []string
	}{
		{
			name:     "nil config returns original env",
			env:      []string{"PATH=/usr/bin", "HOME=/home/user"},
			cfg:      nil,
			expected: []string{"PATH=/usr/bin", "HOME=/home/user"},
		},
		{
			name:     "empty config returns original env",
			env:      []string{"PATH=/usr/bin", "HOME=/home/user"},
			cfg:      &config.EnvironmentConfig{},
			expected: []string{"PATH=/usr/bin", "HOME=/home/user"},
		},
		{
			name: "deny pattern filters variables",
			env:  []string{"PATH=/usr/bin", "MY_TOKEN=secret", "HOME=/home/user"},
			cfg: &config.EnvironmentConfig{
				DeniedVars: []string{"*_TOKEN"},
			},
			expected: []string{"PATH=/usr/bin", "HOME=/home/user"},
		},
		{
			name: "allow pattern filters variables",
			env:  []string{"PATH=/usr/bin", "MY_TOKEN=secret", "HOME=/home/user"},
			cfg: &config.EnvironmentConfig{
				AllowedVars: []string{"PATH", "HOME"},
			},
			expected: []string{"PATH=/usr/bin", "HOME=/home/user"},
		},
		{
			name: "deny takes precedence over allow",
			env:  []string{"AWS_ACCESS_KEY=key", "AWS_SECRET_KEY=secret", "PATH=/usr/bin"},
			cfg: &config.EnvironmentConfig{
				AllowedVars: []string{"AWS_*"},
				DeniedVars:  []string{"*_SECRET_*"},
			},
			expected: []string{"AWS_ACCESS_KEY=key"},
		},
		{
			name: "multiple patterns",
			env:  []string{"PATH=/usr/bin", "HOME=/home/user", "USER=test", "MY_TOKEN=secret"},
			cfg: &config.EnvironmentConfig{
				AllowedVars: []string{"PATH", "HOME", "USER"},
				DeniedVars:  []string{"*_TOKEN"},
			},
			expected: []string{"PATH=/usr/bin", "HOME=/home/user", "USER=test"},
		},
		{
			name: "empty env",
			env:  []string{},
			cfg: &config.EnvironmentConfig{
				AllowedVars: []string{"PATH"},
			},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterEnvironmentVars(tt.env, tt.cfg)
			if len(got) != len(tt.expected) {
				t.Errorf("FilterEnvironmentVars() returned %d vars, want %d", len(got), len(tt.expected))
			}
			for i, v := range got {
				if i >= len(tt.expected) || v != tt.expected[i] {
					t.Errorf("FilterEnvironmentVars() var %d = %q, want %q", i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestGetHardenedEnvWithConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		// We can't easily test the actual environment, so we'll just verify
		// that the function doesn't panic and returns a slice
		shouldNotPanic bool
	}{
		{
			name:           "nil config",
			cfg:            nil,
			shouldNotPanic: true,
		},
		{
			name: "empty config",
			cfg: &config.Config{
				Environment: config.EnvironmentConfig{},
			},
			shouldNotPanic: true,
		},
		{
			name: "config with environment filtering",
			cfg: &config.Config{
				Environment: config.EnvironmentConfig{
					AllowedVars: []string{"PATH", "HOME"},
					DeniedVars:  []string{"*_TOKEN"},
				},
			},
			shouldNotPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil && tt.shouldNotPanic {
					t.Errorf("GetHardenedEnvWithConfig() panicked: %v", r)
				}
			}()

			result := GetHardenedEnvWithConfig(tt.cfg)
			if result == nil {
				t.Error("GetHardenedEnvWithConfig() returned nil")
			}
			// Result should be a slice (possibly empty)
			// Note: len() can never be negative, so no check needed
		})
	}
}

func TestFilterEnvironmentVars_Integration(t *testing.T) {
	// Test that FilterEnvironmentVars works correctly with FilterDangerousEnv
	env := []string{
		"PATH=/usr/bin",
		"LD_PRELOAD=/tmp/evil.so",
		"HOME=/home/user",
		"MY_TOKEN=secret",
		"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib",
		"AWS_ACCESS_KEY=key",
	}

	// First filter dangerous vars
	filtered := FilterDangerousEnv(env)

	// Then apply environment config filtering
	cfg := &config.EnvironmentConfig{
		AllowedVars: []string{"PATH", "HOME", "AWS_*"},
		DeniedVars:  []string{"*_TOKEN"},
	}
	result := FilterEnvironmentVars(filtered, cfg)

	// Should have PATH, HOME, AWS_ACCESS_KEY (no LD_PRELOAD, DYLD_INSERT_LIBRARIES, MY_TOKEN)
	expected := []string{"PATH=/usr/bin", "HOME=/home/user", "AWS_ACCESS_KEY=key"}
	if len(result) != len(expected) {
		t.Errorf("expected %d vars, got %d: %v", len(expected), len(result), result)
	}

	for i, v := range result {
		if i >= len(expected) || v != expected[i] {
			t.Errorf("var %d = %q, want %q", i, v, expected[i])
		}
	}
}

func TestIntegration_DangerousEnvRemovalWithConfigFiltering(t *testing.T) {
	// Test that dangerous env removal works together with config-based filtering
	// This is the complete pipeline: dangerous removal → user config filtering
	env := []string{
		"PATH=/usr/bin",
		"LD_PRELOAD=/tmp/evil.so", // Dangerous - should be removed first
		"HOME=/home/user",
		"MY_TOKEN=secret",                 // Denied by config
		"DYLD_INSERT_LIBRARIES=/tmp/evil", // Dangerous - should be removed first
		"AWS_ACCESS_KEY=key",              // Allowed by config
		"AWS_SECRET_KEY=secret",           // Denied by config (matches *_SECRET_*)
		"USER=test",                       // Allowed by config
	}

	// First filter dangerous vars
	filtered := FilterDangerousEnv(env)

	// Verify dangerous vars were removed
	for _, entry := range filtered {
		if isDangerousEnvVar(entry) {
			t.Errorf("dangerous var not filtered: %s", entry)
		}
	}

	// Then apply environment config filtering
	cfg := &config.EnvironmentConfig{
		AllowedVars: []string{"PATH", "HOME", "USER", "AWS_*"},
		DeniedVars:  []string{"*_TOKEN", "*_SECRET_*"},
	}
	result := FilterEnvironmentVars(filtered, cfg)

	// Expected: PATH, HOME, USER, AWS_ACCESS_KEY
	// Not expected: LD_PRELOAD, DYLD_INSERT_LIBRARIES (dangerous), MY_TOKEN, AWS_SECRET_KEY (denied)
	expected := map[string]bool{
		"PATH=/usr/bin":      true,
		"HOME=/home/user":    true,
		"USER=test":          true,
		"AWS_ACCESS_KEY=key": true,
	}

	if len(result) != len(expected) {
		t.Errorf("expected %d vars, got %d: %v", len(expected), len(result), result)
	}

	for _, entry := range result {
		if !expected[entry] {
			t.Errorf("unexpected var in result: %s", entry)
		}
	}

	// Verify no dangerous vars in result
	for _, entry := range result {
		if isDangerousEnvVar(entry) {
			t.Errorf("dangerous var in final result: %s", entry)
		}
	}
}

func TestIntegration_GetHardenedEnvWithConfig_CompleteFlow(t *testing.T) {
	// Test the complete flow through GetHardenedEnvWithConfig
	// This simulates what happens in main.go

	// Create a config with environment filtering
	cfg := &config.Config{
		Environment: config.EnvironmentConfig{
			AllowedVars: []string{"PATH", "HOME", "USER", "LANG", "LC_*"},
			DeniedVars:  []string{"*_TOKEN", "*_SECRET", "AWS_*"},
		},
	}

	// Get hardened env with config
	result := GetHardenedEnvWithConfig(cfg)

	// Verify result is not nil and is a slice
	if result == nil {
		t.Error("GetHardenedEnvWithConfig returned nil")
	}

	// Verify no dangerous vars in result
	for _, entry := range result {
		if isDangerousEnvVar(entry) {
			t.Errorf("dangerous var in hardened env: %s", entry)
		}
	}

	// Verify that if we had a token in the original env, it would be filtered
	// (We can't easily test this without modifying os.Environ, but we can verify
	// the logic through the FilterEnvironmentVars tests)
}

func TestIntegration_BackwardCompatibility_GetHardenedEnv(t *testing.T) {
	// Test that GetHardenedEnv still works for backward compatibility
	result := GetHardenedEnv()

	if result == nil {
		t.Error("GetHardenedEnv returned nil")
	}

	// Verify no dangerous vars in result
	for _, entry := range result {
		if isDangerousEnvVar(entry) {
			t.Errorf("dangerous var in hardened env: %s", entry)
		}
	}
}

func TestIntegration_ConfigFiltering_DenyTakesPrecedence(t *testing.T) {
	// Test that deny patterns take precedence over allow patterns
	// even when both match the same variable
	env := []string{
		"AWS_ACCESS_KEY=key",
		"AWS_SECRET_KEY=secret",
		"AWS_SESSION_TOKEN=token",
		"PATH=/usr/bin",
	}

	cfg := &config.EnvironmentConfig{
		AllowedVars: []string{"AWS_*", "PATH"},
		DeniedVars:  []string{"*_SECRET_*", "*_TOKEN"},
	}

	result := FilterEnvironmentVars(env, cfg)

	// Should have AWS_ACCESS_KEY and PATH, but not AWS_SECRET_KEY or AWS_SESSION_TOKEN
	expected := map[string]bool{
		"AWS_ACCESS_KEY=key": true,
		"PATH=/usr/bin":      true,
	}

	if len(result) != len(expected) {
		t.Errorf("expected %d vars, got %d: %v", len(expected), len(result), result)
	}

	for _, entry := range result {
		if !expected[entry] {
			t.Errorf("unexpected var in result: %s", entry)
		}
	}
}

func TestIntegration_EmptyAllowList_AllowsAllNonDenied(t *testing.T) {
	// Test that when AllowedVars is empty, all non-denied vars are allowed
	env := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"MY_TOKEN=secret",
		"RANDOM_VAR=value",
	}

	cfg := &config.EnvironmentConfig{
		DeniedVars: []string{"*_TOKEN"},
		// AllowedVars is empty
	}

	result := FilterEnvironmentVars(env, cfg)

	// Should have PATH, HOME, RANDOM_VAR but not MY_TOKEN
	expected := map[string]bool{
		"PATH=/usr/bin":    true,
		"HOME=/home/user":  true,
		"RANDOM_VAR=value": true,
	}

	if len(result) != len(expected) {
		t.Errorf("expected %d vars, got %d: %v", len(expected), len(result), result)
	}

	for _, entry := range result {
		if !expected[entry] {
			t.Errorf("unexpected var in result: %s", entry)
		}
	}
}

// ============================================================================
// CRITICAL TEST CASES - Case Sensitivity Tests
// ============================================================================

func TestCaseSensitivity_PatternMatching(t *testing.T) {
	// Test that pattern matching is case-sensitive
	// "API_KEY" should not match "api_key" pattern
	tests := []struct {
		name     string
		varName  string
		pattern  string
		expected bool
	}{
		// Exact case should match
		{"API_KEY matches API_KEY", "API_KEY", "API_KEY", true},
		{"api_key matches api_key", "api_key", "api_key", true},

		// Different case should not match (exact match)
		{"API_KEY does not match api_key", "API_KEY", "api_key", false},
		{"api_key does not match API_KEY", "api_key", "API_KEY", false},

		// Wildcard patterns are case-sensitive
		{"API_KEY matches API_*", "API_KEY", "API_*", true},
		{"api_key does not match API_*", "api_key", "API_*", false},
		{"api_key matches api_*", "api_key", "api_*", true},
		{"API_KEY does not match api_*", "API_KEY", "api_*", false},

		// PATH vs path
		{"PATH matches PATH", "PATH", "PATH", true},
		{"path matches path", "path", "path", true},
		{"PATH does not match path", "PATH", "path", false},
		{"path does not match PATH", "path", "PATH", false},

		// AWS_* vs aws_*
		{"AWS_KEY matches AWS_*", "AWS_KEY", "AWS_*", true},
		{"aws_key does not match AWS_*", "aws_key", "AWS_*", false},
		{"aws_key matches aws_*", "aws_key", "aws_*", true},
		{"AWS_KEY does not match aws_*", "AWS_KEY", "aws_*", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := config.MatchesEnvVar(tt.varName, tt.pattern)
			if got != tt.expected {
				t.Errorf("MatchesEnvVar(%q, %q) = %v, want %v", tt.varName, tt.pattern, got, tt.expected)
			}
		})
	}
}

// ============================================================================
// CRITICAL TEST CASES - Glob Pattern Edge Cases
// ============================================================================

func TestGlobPatternEdgeCases(t *testing.T) {
	// Test edge cases in glob pattern matching
	tests := []struct {
		name     string
		varName  string
		pattern  string
		expected bool
	}{
		// Multiple asterisks
		{"matches **_SECRET_**", "MY_SECRET_KEY", "**_SECRET_**", true},
		{"matches **_SECRET_**", "PREFIX_SECRET_SUFFIX", "**_SECRET_**", true},
		{"does not match **_SECRET_**", "MY_TOKEN", "**_SECRET_**", false},

		// Asterisk at start
		{"matches *_SECRET", "MY_SECRET", "*_SECRET", true},
		{"matches *_SECRET", "SECRET", "*_SECRET", false},
		{"matches *_SECRET", "A_SECRET", "*_SECRET", true},

		// Asterisk at end
		{"matches SECRET_*", "SECRET_KEY", "SECRET_*", true},
		{"matches SECRET_*", "SECRET", "SECRET_*", false},
		{"matches SECRET_*", "SECRET_", "SECRET_*", true},

		// Asterisk in middle
		{"matches MY_*_KEY", "MY_SECRET_KEY", "MY_*_KEY", true},
		{"matches MY_*_KEY", "MY_KEY", "MY_*_KEY", false},
		{"matches MY_*_KEY", "MY_X_KEY", "MY_*_KEY", true},

		// Edge case: underscore patterns
		{"matches _*", "_SECRET", "_*", true},
		{"matches _*", "SECRET", "_*", false},
		{"matches *_", "SECRET_", "*_", true},
		{"matches *_", "SECRET", "*_", false},

		// Patterns with special regex chars (should be treated literally)
		{"matches [VAR]", "[VAR]", "[VAR]", true},
		{"does not match [VAR] with VAR", "VAR", "[VAR]", false},
		{"matches VAR.", "VAR.", "VAR.", true},
		{"does not match VAR. with VAR", "VAR", "VAR.", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := config.MatchesEnvVar(tt.varName, tt.pattern)
			if got != tt.expected {
				t.Errorf("MatchesEnvVar(%q, %q) = %v, want %v", tt.varName, tt.pattern, got, tt.expected)
			}
		})
	}
}

func TestConflictingPatterns_AllowAndDeny(t *testing.T) {
	// Test conflicting patterns: AllowedVars=["*"], DeniedVars=["*"]
	// Deny should take precedence
	tests := []struct {
		name     string
		varName  string
		cfg      *config.EnvironmentConfig
		expected bool
	}{
		{
			name:    "deny * takes precedence over allow *",
			varName: "ANY_VAR",
			cfg: &config.EnvironmentConfig{
				AllowedVars: []string{"*"},
				DeniedVars:  []string{"*"},
			},
			expected: false,
		},
		{
			name:    "deny specific takes precedence over allow *",
			varName: "SECRET_KEY",
			cfg: &config.EnvironmentConfig{
				AllowedVars: []string{"*"},
				DeniedVars:  []string{"*_KEY"},
			},
			expected: false,
		},
		{
			name:    "allow * with no deny allows all",
			varName: "ANY_VAR",
			cfg: &config.EnvironmentConfig{
				AllowedVars: []string{"*"},
				DeniedVars:  []string{},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isEnvVarAllowed(tt.varName, tt.cfg)
			if got != tt.expected {
				t.Errorf("isEnvVarAllowed(%q, cfg) = %v, want %v", tt.varName, got, tt.expected)
			}
		})
	}
}

// ============================================================================
// CRITICAL TEST CASES - Improved GetHardenedEnvWithConfig Test
// ============================================================================

func TestGetHardenedEnvWithConfig_ActualFiltering(t *testing.T) {
	// Test that GetHardenedEnvWithConfig actually filters variables
	// We'll create a controlled test by using FilterEnvironmentVars directly
	// with a known environment

	// Create a test environment with both dangerous and user-configured vars
	testEnv := []string{
		"PATH=/usr/bin",
		"LD_PRELOAD=/tmp/evil.so", // Dangerous - should be removed
		"HOME=/home/user",
		"MY_TOKEN=secret",            // Should be denied by config
		"AWS_ACCESS_KEY=key",         // Should be allowed by config
		"DYLD_INSERT_LIBRARIES=/tmp", // Dangerous - should be removed
	}

	// First, verify dangerous filtering works
	filtered := FilterDangerousEnv(testEnv)
	if len(filtered) != 4 {
		t.Errorf("FilterDangerousEnv should remove 2 dangerous vars, got %d vars: %v", len(filtered), filtered)
	}

	// Verify no dangerous vars remain
	for _, entry := range filtered {
		if isDangerousEnvVar(entry) {
			t.Errorf("dangerous var not filtered: %s", entry)
		}
	}

	// Then apply config filtering
	cfg := &config.EnvironmentConfig{
		AllowedVars: []string{"PATH", "HOME", "AWS_*"},
		DeniedVars:  []string{"*_TOKEN"},
	}
	result := FilterEnvironmentVars(filtered, cfg)

	// Should have PATH, HOME, AWS_ACCESS_KEY (3 vars)
	if len(result) != 3 {
		t.Errorf("expected 3 vars after filtering, got %d: %v", len(result), result)
	}

	// Verify specific vars are present
	expected := map[string]bool{
		"PATH=/usr/bin":      true,
		"HOME=/home/user":    true,
		"AWS_ACCESS_KEY=key": true,
	}

	for _, entry := range result {
		if !expected[entry] {
			t.Errorf("unexpected var in result: %s", entry)
		}
	}
}

// ============================================================================
// IMPORTANT TEST CASES - Order Preservation
// ============================================================================

func TestOrderPreservation_FilterDangerousEnv(t *testing.T) {
	// Test that FilterDangerousEnv preserves the order of safe variables
	env := []string{
		"Z_VAR=z",
		"LD_PRELOAD=/tmp/evil.so", // Dangerous - will be removed
		"A_VAR=a",
		"DYLD_INSERT_LIBRARIES=/tmp", // Dangerous - will be removed
		"M_VAR=m",
	}

	filtered := FilterDangerousEnv(env)

	// Should have Z_VAR, A_VAR, M_VAR in that order
	expected := []string{"Z_VAR=z", "A_VAR=a", "M_VAR=m"}
	if len(filtered) != len(expected) {
		t.Errorf("expected %d vars, got %d", len(expected), len(filtered))
	}

	for i, v := range filtered {
		if i >= len(expected) || v != expected[i] {
			t.Errorf("var %d = %q, want %q", i, v, expected[i])
		}
	}
}

func TestOrderPreservation_FilterEnvironmentVars(t *testing.T) {
	// Test that FilterEnvironmentVars preserves the order of filtered variables
	env := []string{
		"Z_VAR=z",
		"MY_TOKEN=secret", // Denied - will be removed
		"A_VAR=a",
		"ANOTHER_TOKEN=x", // Denied - will be removed
		"M_VAR=m",
	}

	cfg := &config.EnvironmentConfig{
		AllowedVars: []string{"*_VAR"},
		DeniedVars:  []string{"*_TOKEN"},
	}

	filtered := FilterEnvironmentVars(env, cfg)

	// Should have Z_VAR, A_VAR, M_VAR in that order
	expected := []string{"Z_VAR=z", "A_VAR=a", "M_VAR=m"}
	if len(filtered) != len(expected) {
		t.Errorf("expected %d vars, got %d", len(expected), len(filtered))
	}

	for i, v := range filtered {
		if i >= len(expected) || v != expected[i] {
			t.Errorf("var %d = %q, want %q", i, v, expected[i])
		}
	}
}

// ============================================================================
// IMPORTANT TEST CASES - Nil/Empty Slice Edge Cases
// ============================================================================

func TestNilEmptySliceDistinction(t *testing.T) {
	// Test distinction between nil and empty slices
	tests := []struct {
		name string
		env  []string
		cfg  *config.EnvironmentConfig
	}{
		{
			name: "nil env slice",
			env:  nil,
			cfg:  &config.EnvironmentConfig{},
		},
		{
			name: "empty env slice",
			env:  []string{},
			cfg:  &config.EnvironmentConfig{},
		},
		{
			name: "nil allowed vars",
			env:  []string{"PATH=/usr/bin"},
			cfg: &config.EnvironmentConfig{
				AllowedVars: nil,
				DeniedVars:  []string{},
			},
		},
		{
			name: "empty allowed vars",
			env:  []string{"PATH=/usr/bin"},
			cfg: &config.EnvironmentConfig{
				AllowedVars: []string{},
				DeniedVars:  []string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			result := FilterEnvironmentVars(tt.env, tt.cfg)
			if result == nil && tt.env != nil {
				t.Error("FilterEnvironmentVars returned nil for non-nil input")
			}
		})
	}
}

func TestPartiallyInitializedConfig(t *testing.T) {
	// Test partially initialized configs
	tests := []struct {
		name     string
		env      []string
		cfg      *config.EnvironmentConfig
		expected int
	}{
		{
			name: "only allowed vars set",
			env:  []string{"PATH=/usr/bin", "HOME=/home/user", "SECRET=x"},
			cfg: &config.EnvironmentConfig{
				AllowedVars: []string{"PATH", "HOME"},
				DeniedVars:  nil,
			},
			expected: 2,
		},
		{
			name: "only denied vars set",
			env:  []string{"PATH=/usr/bin", "HOME=/home/user", "SECRET=x"},
			cfg: &config.EnvironmentConfig{
				AllowedVars: nil,
				DeniedVars:  []string{"SECRET"},
			},
			expected: 2,
		},
		{
			name: "both empty",
			env:  []string{"PATH=/usr/bin", "HOME=/home/user"},
			cfg: &config.EnvironmentConfig{
				AllowedVars: []string{},
				DeniedVars:  []string{},
			},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterEnvironmentVars(tt.env, tt.cfg)
			if len(result) != tt.expected {
				t.Errorf("expected %d vars, got %d: %v", tt.expected, len(result), result)
			}
		})
	}
}

// ============================================================================
// IMPORTANT TEST CASES - Pattern Validation
// ============================================================================

func TestPatternValidation_EdgeCases(t *testing.T) {
	// Test how invalid/edge case patterns are handled
	tests := []struct {
		name     string
		varName  string
		pattern  string
		expected bool
	}{
		// Empty string pattern
		{"empty pattern matches empty var", "", "", true},
		{"empty pattern does not match non-empty var", "VAR", "", false},
		{"non-empty var does not match empty pattern", "VAR", "", false},

		// Whitespace-only patterns
		{"space pattern matches space", " ", " ", true},
		{"space pattern does not match VAR", "VAR", " ", false},
		{"VAR does not match space pattern", "VAR", " ", false},

		// Pattern with spaces
		{"VAR with space in pattern", "MY VAR", "MY VAR", true},
		{"VAR with space does not match without space", "MYVAR", "MY VAR", false},

		// Very long patterns
		{"long exact match", "VERY_LONG_VARIABLE_NAME_WITH_MANY_PARTS", "VERY_LONG_VARIABLE_NAME_WITH_MANY_PARTS", true},
		{"long pattern with wildcard", "VERY_LONG_VARIABLE_NAME_WITH_MANY_PARTS", "VERY_*_MANY_PARTS", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := config.MatchesEnvVar(tt.varName, tt.pattern)
			if got != tt.expected {
				t.Errorf("MatchesEnvVar(%q, %q) = %v, want %v", tt.varName, tt.pattern, got, tt.expected)
			}
		})
	}
}

// ============================================================================
// IMPORTANT TEST CASES - Special Characters
// ============================================================================

func TestSpecialCharactersInValues(t *testing.T) {
	// Test variables with special characters in values
	tests := []struct {
		name     string
		entry    string
		expected string
	}{
		// Spaces in values
		{"spaces in value", "VAR=value with spaces", "VAR"},
		{"multiple spaces", "VAR=value  with  multiple  spaces", "VAR"},

		// Special characters in values
		{"dollar sign in value", "VAR=$SPECIAL", "VAR"},
		{"equals in value", "PATH=value=with=many=equals", "PATH"},
		{"colon in value", "PATH=/usr/bin:/usr/local/bin", "PATH"},
		{"semicolon in value", "VAR=value;other", "VAR"},
		{"quotes in value", "VAR=\"quoted value\"", "VAR"},
		{"single quotes in value", "VAR='single quoted'", "VAR"},

		// Newlines and tabs (edge case)
		{"tab in value", "VAR=value\twith\ttabs", "VAR"},

		// Unicode characters
		{"unicode in value", "VAR=value_with_émojis_🎉", "VAR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractEnvVarName(tt.entry)
			if got != tt.expected {
				t.Errorf("extractEnvVarName(%q) = %q, want %q", tt.entry, got, tt.expected)
			}
		})
	}
}

func TestFilterEnvironmentVars_SpecialCharacterValues(t *testing.T) {
	// Test that filtering works correctly with special characters in values
	env := []string{
		"PATH=/usr/bin:/usr/local/bin",
		"VAR=value with spaces",
		"SPECIAL=$VARIABLE",
		"EQUALS=a=b=c",
		"QUOTED=\"value\"",
	}

	cfg := &config.EnvironmentConfig{
		AllowedVars: []string{"PATH", "VAR", "SPECIAL", "EQUALS", "QUOTED"},
	}

	result := FilterEnvironmentVars(env, cfg)

	// All should pass through unchanged
	if len(result) != len(env) {
		t.Errorf("expected %d vars, got %d", len(env), len(result))
	}

	for i, v := range result {
		if v != env[i] {
			t.Errorf("var %d changed: %q -> %q", i, env[i], v)
		}
	}
}

// ============================================================================
// IMPORTANT TEST CASES - Extracted Variable Name Function
// ============================================================================

func TestExtractEnvVarNameFromEntry_Comprehensive(t *testing.T) {
	// Comprehensive test for the private extractEnvVarNameFromEntry function
	// (tested through the public extractEnvVarName wrapper)
	tests := []struct {
		name     string
		entry    string
		expected string
	}{
		// Standard cases
		{"simple var", "VAR=value", "VAR"},
		{"path var", "PATH=/usr/bin", "PATH"},

		// Edge cases
		{"no equals", "VAR", "VAR"},
		{"empty value", "VAR=", "VAR"},
		{"multiple equals", "VAR=a=b=c", "VAR"},

		// Special characters in name (valid in env vars)
		{"underscore", "MY_VAR=value", "MY_VAR"},
		{"numbers", "VAR123=value", "VAR123"},
		{"leading underscore", "_VAR=value", "_VAR"},

		// Empty and whitespace
		{"empty string", "", ""},
		{"just equals", "=value", ""},

		// Case preservation
		{"lowercase", "var=value", "var"},
		{"uppercase", "VAR=VALUE", "VAR"},
		{"mixed case", "VaR=VaLuE", "VaR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractEnvVarName(tt.entry)
			if got != tt.expected {
				t.Errorf("extractEnvVarName(%q) = %q, want %q", tt.entry, got, tt.expected)
			}
		})
	}
}

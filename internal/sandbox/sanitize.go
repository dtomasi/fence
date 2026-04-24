package sandbox

import (
	"os"
	"runtime"
	"strings"

	"github.com/Use-Tusk/fence/internal/config"
)

// DangerousEnvPrefixes lists environment variable prefixes that can be used
// to subvert library loading and should be stripped from sandboxed processes.
//
// - LD_* (Linux): LD_PRELOAD, LD_LIBRARY_PATH can inject malicious shared libraries
// - DYLD_* (macOS): DYLD_INSERT_LIBRARIES, DYLD_LIBRARY_PATH can inject dylibs
var DangerousEnvPrefixes = []string{
	"LD_",   // Linux dynamic linker
	"DYLD_", // macOS dynamic linker
}

// DangerousEnvVars lists specific environment variables that should be stripped.
var DangerousEnvVars = []string{
	"LD_PRELOAD",
	"LD_LIBRARY_PATH",
	"LD_AUDIT",
	"LD_DEBUG",
	"LD_DEBUG_OUTPUT",
	"LD_DYNAMIC_WEAK",
	"LD_ORIGIN_PATH",
	"LD_PROFILE",
	"LD_PROFILE_OUTPUT",
	"LD_SHOW_AUXV",
	"LD_TRACE_LOADED_OBJECTS",
	"DYLD_INSERT_LIBRARIES",
	"DYLD_LIBRARY_PATH",
	"DYLD_FRAMEWORK_PATH",
	"DYLD_FALLBACK_LIBRARY_PATH",
	"DYLD_FALLBACK_FRAMEWORK_PATH",
	"DYLD_IMAGE_SUFFIX",
	"DYLD_FORCE_FLAT_NAMESPACE",
	"DYLD_PRINT_LIBRARIES",
	"DYLD_PRINT_APIS",
}

// GetHardenedEnv returns a copy of the current environment with dangerous
// variables removed. This prevents library injection attacks where a malicious
// agent writes a .so/.dylib and then uses LD_PRELOAD/DYLD_INSERT_LIBRARIES
// in a subsequent command.
func GetHardenedEnv() []string {
	return FilterDangerousEnv(os.Environ())
}

// FilterDangerousEnv filters out dangerous environment variables from the given slice.
func FilterDangerousEnv(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, e := range env {
		if !isDangerousEnvVar(e) {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// FilterEnvironmentVars filters environment variables based on configuration.
// Follows deny-before-allow precedence like other filtering in fence.
// Returns original env if no config provided.
func FilterEnvironmentVars(env []string, cfg *config.EnvironmentConfig) []string {
	if cfg == nil || (len(cfg.DeniedVars) == 0 && len(cfg.AllowedVars) == 0) {
		return env
	}

	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		varName := extractEnvVarName(entry)
		if isEnvVarAllowed(varName, cfg) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

// extractEnvVarNameFromEntry extracts the variable name from an environment entry (KEY=VALUE).
// This is a private helper function used by multiple functions to parse env entries.
func extractEnvVarNameFromEntry(entry string) string {
	if idx := strings.Index(entry, "="); idx != -1 {
		return entry[:idx]
	}
	return entry
}

// isDangerousEnvVar checks if an environment variable entry (KEY=VALUE) is dangerous.
func isDangerousEnvVar(entry string) bool {
	// Extract the key from the entry
	key := extractEnvVarNameFromEntry(entry)

	// Check against known dangerous prefixes
	for _, prefix := range DangerousEnvPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}

	// Check against specific dangerous vars
	for _, dangerous := range DangerousEnvVars {
		if key == dangerous {
			return true
		}
	}

	return false
}

// GetStrippedEnvVars returns a list of environment variable names that were
// stripped from the given environment. Useful for debug logging.
func GetStrippedEnvVars(env []string) []string {
	var stripped []string
	for _, e := range env {
		if isDangerousEnvVar(e) {
			// Extract just the key using the shared function
			stripped = append(stripped, extractEnvVarNameFromEntry(e))
		}
	}
	return stripped
}

// isEnvVarAllowed checks if an environment variable is allowed based on configuration.
// Implements deny-before-allow precedence: denied patterns are checked first.
func isEnvVarAllowed(varName string, cfg *config.EnvironmentConfig) bool {
	// Check denied patterns first (deny takes precedence)
	for _, pattern := range cfg.DeniedVars {
		if config.MatchesEnvVar(varName, pattern) {
			return false
		}
	}

	// If no allow patterns configured, allow by default (after deny check)
	if len(cfg.AllowedVars) == 0 {
		return true
	}

	// Check allowed patterns
	for _, pattern := range cfg.AllowedVars {
		if config.MatchesEnvVar(varName, pattern) {
			return true
		}
	}

	return false // Not in allow list
}

// extractEnvVarName extracts the variable name from an environment entry (KEY=VALUE).
// This is a public wrapper around extractEnvVarNameFromEntry for backward compatibility.
func extractEnvVarName(entry string) string {
	return extractEnvVarNameFromEntry(entry)
}

// GetHardenedEnvWithConfig returns environment with dangerous variables removed
// and user-configured environment filtering applied.
// First removes dangerous variables (mandatory security filtering),
// then applies user-configured environment filtering.
func GetHardenedEnvWithConfig(cfg *config.Config) []string {
	env := os.Environ()

	// First, remove dangerous variables (mandatory security filtering)
	filtered := FilterDangerousEnv(env)

	// Then apply user-configured environment filtering
	if cfg != nil {
		filtered = FilterEnvironmentVars(filtered, &cfg.Environment)
	}

	return filtered
}

// HardeningFeatures returns a description of environment sanitization applied on this platform.
func HardeningFeatures() string {
	switch runtime.GOOS {
	case "linux":
		return "env-filter(LD_*)"
	case "darwin":
		return "env-filter(DYLD_*)"
	default:
		return "env-filter"
	}
}

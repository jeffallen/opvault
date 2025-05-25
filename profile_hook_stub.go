//go:build !testonly

package opvault

// assignToTestHook is a stub for non-test builds.
func assignToTestHook(_ []byte) {
	// Do nothing
}

//go:build testonly

package opvault

// testHookMasterPasswordBytes is used by tests to get a reference to the
// master password bytes used during Profile.Unlock.
var testHookMasterPasswordBytes []byte

func assignToTestHook(pBytes []byte) {
	testHookMasterPasswordBytes = pBytes
}

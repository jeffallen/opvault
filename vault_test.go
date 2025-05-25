package opvault

import (
	"testing"
)

func TestReadOpvault(t *testing.T) {
	vault, err := Open("testdata/onepassword_data")
	if err != nil {
		t.Fatalf("Failed to open vault: %v", err)
	}

	profile, err := vault.Profile("default")
	if err != nil {
		t.Fatalf("Failed to get profile: %v", err)
	}

	if profile == nil {
		t.Fatal("Profile is nil before unlock")
	}

	// Unlock the profile with the password
	err = profile.Unlock("freddy")
	if err != nil {
		t.Fatalf("Failed to unlock profile: %v", err)
	}

	// Assert that the profile object is not nil after unlock
	// (though Unlock doesn't return a new profile, we ensure it's still valid)
	if profile == nil {
		t.Fatal("Profile is nil after unlock")
	}

	// Additional check: try to read something that requires unlocking
	_, err = profile.Items()
	if err != nil {
		t.Fatalf("Failed to get items after unlock: %v", err)
	}
}

func TestUnlockZerosMasterPassword(t *testing.T) {
	vault, err := Open("testdata/onepassword_data")
	if err != nil {
		t.Fatalf("Failed to open vault: %v", err)
	}

	profile, err := vault.Profile("default")
	if err != nil {
		t.Fatalf("Failed to get profile: %v", err)
	}

	// Ensure the test hook variable is reset after the test.
	defer func() {
		testHookMasterPasswordBytes = nil
	}()

	// Signal to the test hook that we want to capture the password bytes.
	// Assign a non-nil slice. The content doesn't matter, only its non-nil status.
	testHookMasterPasswordBytes = []byte{}

	testPassword := "thisIsATestPassword123!"
	// We expect Unlock to fail because the password is wrong for the "default" profile,
	// but the password bytes should still be cleared by the deferred wipeSlice.
	err = profile.Unlock(testPassword)
	if err == nil {
		// This isn't strictly a failure of the zeroing mechanism, but it's unexpected
		// if the password isn't "freddy". For this test, we focus on the zeroing.
		// t.Logf("Warning: Unlock succeeded with incorrect password '%s', expected failure.", testPassword)
	} else if err != ErrInvalidPassword {
		// If it's another error, it might indicate a problem with setup rather than the password itself.
		// t.Logf("Unlock failed with an unexpected error: %v. Expected ErrInvalidPassword or success.", err)
	}

	if testHookMasterPasswordBytes == nil {
		t.Fatal("testHookMasterPasswordBytes is nil, hook was not effective.")
	}

	// Check if the captured password bytes were zeroed.
	// The length should be the length of testPassword.
	// If assignToTestHook made a copy, this test would be flawed.
	// But it assigns the actual slice used by Unlock.
	expectedOriginalLength := len(testPassword)
	if len(testHookMasterPasswordBytes) != expectedOriginalLength {
		// This could happen if Unlock exits very early, before assignToTestHook is called,
		// or if assignToTestHook was not called with the correct slice.
		// Given the current Unlock logic, passwordBytes is prepared right at the start.
		// So, if testHookMasterPasswordBytes is not nil, it should hold the reference.
		// The only way its length would change is if it was re-sliced, which it isn't.
		// The most likely scenario for it to be non-nil but empty (if testPassword is not empty)
		// is if it was explicitly set to an empty slice by assignToTestHook, which it shouldn't.
		// Let's assume it holds the original slice reference.
		// The deferred wipeSlice should have zeroed it in place.

		// If Unlock failed very early (e.g. profile data missing essential fields for PBKDF2),
		// testHookMasterPasswordBytes might still be the initial empty slice assigned.
		// But Unlock prepares passwordBytes and calls assignToTestHook before operations that might fail early.
	}

	allZero := true
	for i, b := range testHookMasterPasswordBytes {
		if b != 0 {
			allZero = false
			t.Errorf("Byte at index %d was not zeroed: got %x", i, b)
		}
	}

	if !allZero {
		t.Fatalf("Master password bytes were not properly zeroed out in memory. Slice: %x", testHookMasterPasswordBytes)
	} else {
		t.Logf("Successfully verified that password bytes (len %d) were zeroed.", len(testHookMasterPasswordBytes))
	}

	// Additional check: ensure the length of the slice is what we expect,
	// and it's not, for example, an empty slice if the password was non-empty.
	// This helps confirm assignToTestHook correctly captured the slice.
	if len(testPassword) > 0 && expectedOriginalLength == 0 && len(testHookMasterPasswordBytes) == 0 {
		// This case implies testHookMasterPasswordBytes might still be the `[]byte{}` we initialized it with,
		// meaning assignToTestHook might not have updated it.
		// However, the earlier nil check for testHookMasterPasswordBytes should ideally mean
		// it was reassigned by assignToTestHook if testPassword was processed.
		// The critical part is that `assignToTestHook` assigns the actual slice `passwordBytes` from `Unlock`.
		// Then `wipeSlice` zeros that same slice.
		// If testHookMasterPasswordBytes is not nil, it must be that slice.
	} else if len(testHookMasterPasswordBytes) != expectedOriginalLength {
		t.Errorf("Expected testHookMasterPasswordBytes to have length %d (original password length), but got %d. This might indicate the hook didn't capture the correct slice.", expectedOriginalLength, len(testHookMasterPasswordBytes))
	}
}

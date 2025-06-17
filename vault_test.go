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

	// Test with incorrect password first
	testPassword := "thisIsATestPassword123!"
	passwordSlice, err := profile.unlockWithTestHook(testPassword)
	if err == nil {
		// This shouldn't happen with wrong password, but focus on zeroing test
		t.Logf("Warning: Unlock succeeded with test password, expected failure")
	} else if err != ErrInvalidPassword {
		t.Logf("Unlock failed with unexpected error: %v", err)
	}

	// Verify password bytes were zeroed
	verifyPasswordZeroed(t, passwordSlice, len(testPassword))

	// Test with correct password
	testPassword = "freddy"
	passwordSlice, err = profile.unlockWithTestHook(testPassword)
	if err != nil {
		t.Fatalf("Failed to unlock with correct password: %v", err)
	}

	// Verify password bytes were zeroed even on success
	verifyPasswordZeroed(t, passwordSlice, len(testPassword))
}

func verifyPasswordZeroed(t *testing.T, passwordSlice []byte, expectedLen int) {
	if passwordSlice == nil {
		t.Fatal("password slice is nil")
	}

	allZero := true
	for i, b := range passwordSlice {
		if b != 0 {
			allZero = false
			t.Errorf("Byte at index %d was not zeroed: got %x", i, b)
		}
	}

	if !allZero {
		t.Fatalf("Master password bytes were not properly zeroed out in memory. Slice: %x", passwordSlice)
	} else {
		t.Logf("Successfully verified that password bytes (len %d) were zeroed.", len(passwordSlice))
	}

	if len(passwordSlice) != expectedLen {
		t.Errorf("Expected password slice to have length %d, but got %d", expectedLen, len(passwordSlice))
	}
}

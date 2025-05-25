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
		testPeek = nil
	}()

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

	if testPeek == nil {
		t.Fatal("testPeek is nil")
	}

	allZero := true
	for i, b := range testPeek {
		if b != 0 {
			allZero = false
			t.Errorf("Byte at index %d was not zeroed: got %x", i, b)
		}
	}

	if !allZero {
		t.Fatalf("Master password bytes were not properly zeroed out in memory. Slice: %x", testPeek)
	} else {
		t.Logf("Successfully verified that password bytes (len %d) were zeroed.", len(testPeek))
	}

	if len(testPeek) != len(testPassword) {
		t.Errorf("Expected testHookMasterPasswordBytes to have length %d (original password length), but got %d. This might indicate the hook didn't capture the correct slice.", len(testPassword), len(testPeek))
	}

	testPassword = "freddy"

	err = profile.Unlock(testPassword)
	if err != nil {
		t.Fatal(err)
	}

	if testPeek == nil {
		t.Fatal("testPeek is nil")
	}

	allZero = true
	for i, b := range testPeek {
		if b != 0 {
			allZero = false
			t.Errorf("Byte at index %d was not zeroed: got %x", i, b)
		}
	}

	if !allZero {
		t.Fatalf("Master password bytes were not properly zeroed out in memory. Slice: %x", testPeek)
	} else {
		t.Logf("Successfully verified that password bytes (len %d) were zeroed.", len(testPeek))
	}

	if len(testPeek) != len(testPassword) {
		t.Errorf("Expected testHookMasterPasswordBytes to have length %d (original password length), but got %d. This might indicate the hook didn't capture the correct slice.", len(testPassword), len(testPeek))
	}
}

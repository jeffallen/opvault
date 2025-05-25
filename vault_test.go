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

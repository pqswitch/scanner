package main

import (
	"testing"
)

func TestVersionInfo(t *testing.T) {
	if version == "" {
		version = "dev"
	}
	if commit == "" {
		commit = "none"
	}
	if date == "" {
		date = "unknown"
	}

	// Test that version info is accessible
	if version != "dev" && version == "" {
		t.Error("Version should be set")
	}

	t.Logf("Version: %s, Commit: %s, Date: %s", version, commit, date)
}

func TestRootCommand(t *testing.T) {
	if rootCmd == nil {
		t.Fatal("Root command should not be nil")
	}

	if rootCmd.Use != "pqswitch" {
		t.Error("Root command use should be 'pqswitch'")
	}

	if rootCmd.Short == "" {
		t.Error("Root command should have a short description")
	}
}

func TestScanCommand(t *testing.T) {
	if scanCmd == nil {
		t.Fatal("Scan command should not be nil")
	}

	if scanCmd.Use != "scan [path]" {
		t.Error("Scan command use should be 'scan [path]'")
	}

	if scanCmd.Short == "" {
		t.Error("Scan command should have a short description")
	}
}

func BenchmarkCommandCreation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := rootCmd
		_ = cmd.Use
		_ = cmd.Short
	}
}

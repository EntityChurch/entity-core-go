package main

import (
	"fmt"
	"os"
)

func runBuildFixture(args []string) error {
	var diagPath, outPath string
	if err := parseFlags("build-fixture", args, map[string]*string{
		"diag": &diagPath,
		"out":  &outPath,
	}); err != nil {
		return err
	}
	if diagPath == "" || outPath == "" {
		return fmt.Errorf("build-fixture: --diag and --out are required")
	}

	src, err := os.ReadFile(diagPath)
	if err != nil {
		return fmt.Errorf("read diag: %w", err)
	}
	val, err := ParseDiag(string(src))
	if err != nil {
		return fmt.Errorf("parse diag: %w", err)
	}
	arr, ok := val.([]interface{})
	if !ok {
		return fmt.Errorf("expected top-level array, got %T", val)
	}

	encoded, err := encodeCanonical(arr)
	if err != nil {
		return fmt.Errorf("encode canonical: %w", err)
	}

	if err := os.WriteFile(outPath, encoded, 0644); err != nil {
		return fmt.Errorf("write fixture: %w", err)
	}

	fmt.Printf("build-fixture: wrote %s (%d vectors, %d bytes)\n",
		outPath, len(arr), len(encoded))
	return nil
}

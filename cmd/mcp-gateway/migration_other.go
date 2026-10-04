//go:build !linux && !darwin

package main

import "errors"

func publishMigration(from, to string) error {
	return errors.New("offline migration requires Linux or macOS for atomic no-replace publication")
}

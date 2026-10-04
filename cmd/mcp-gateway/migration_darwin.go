package main

import "golang.org/x/sys/unix"

func publishMigration(from, to string) error {
	return unix.RenamexNp(from, to, unix.RENAME_EXCL)
}

//go:build !linux && !darwin

package ipsec

import "os"

func ownedByCurrentUser(os.FileInfo) bool                { return false }
func journalPrivate(os.FileInfo, bool) bool              { return false }
func journalOpenNoFollow(string, bool) (*os.File, error) { return nil, ErrRuntimeJournal }
func journalLock(*os.File) error                         { return ErrRuntimeJournal }
func journalUnlock(*os.File)                             {}

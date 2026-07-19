//go:build !linux && !darwin

package yumrepo

func installImmutable(staged, dest string) error {
	return ErrAtomicUnsupported
}

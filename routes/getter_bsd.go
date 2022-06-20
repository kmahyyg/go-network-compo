//go:build openbsd || freebsd || netbsd || darwin

package routes

func Retrieve() ([]NetRoute, error) {
	return nil, nil
}

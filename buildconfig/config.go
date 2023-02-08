//go:build !nogui

package buildconfig

func NoGui() bool {
	return false
}

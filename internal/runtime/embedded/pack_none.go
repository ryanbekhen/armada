//go:build !(bundle && linux && (amd64 || arm64))

package embedded

// bundledPack is empty in builds without the bundle tag (development and
// unit tests): the runtime binaries then come from `armadad runtime --bin-dir`.
var bundledPack []byte

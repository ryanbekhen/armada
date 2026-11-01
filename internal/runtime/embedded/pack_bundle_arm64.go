//go:build bundle && linux && arm64

package embedded

import _ "embed"

//go:embed bundle/linux_arm64.pack
var bundledPack []byte

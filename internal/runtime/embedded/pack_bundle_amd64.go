//go:build bundle && linux && amd64

package embedded

import _ "embed"

//go:embed bundle/linux_amd64.pack
var bundledPack []byte

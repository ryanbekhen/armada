package agent

import (
	"bytes"
	"errors"
	"maps"
	"strings"
	"testing"
)

const hdiutilInfo = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>framework</key>
	<string>705</string>
	<key>images</key>
	<array>
		<dict>
			<key>image-path</key>
			<string>/Users/x/Downloads/tool.dmg</string>
			<key>removable</key>
			<true/>
			<key>system-entities</key>
			<array>
				<dict>
					<key>dev-entry</key>
					<string>/dev/disk4</string>
				</dict>
			</array>
		</dict>
		<dict>
			<key>image-path</key>
			<string>ram://131072</string>
			<key>owner-uid</key>
			<integer>501</integer>
			<key>system-entities</key>
			<array>
				<dict>
					<key>dev-entry</key>
					<string>/dev/disk8</string>
				</dict>
				<dict>
					<key>dev-entry</key>
					<string>/dev/disk8s1</string>
				</dict>
			</array>
		</dict>
	</array>
</dict>
</plist>
`

func TestParseRAMDisks(t *testing.T) {
	t.Parallel()
	got, err := parseRAMDisks([]byte(hdiutilInfo))
	if err != nil {
		t.Fatal(err)
	}
	// Only whole disks of ram:// images: not the disk image, not slices.
	if want := map[string]bool{"/dev/disk8": true}; !maps.Equal(got, want) {
		t.Errorf("RAM disks = %v, want %v", got, want)
	}
	if got, err := parseRAMDisks([]byte(`<plist version="1.0"><dict/></plist>`)); err != nil || len(got) != 0 {
		t.Errorf("no images: %v, %v", got, err)
	}
}

func TestDecodePlistRefusesMalformedInput(t *testing.T) {
	t.Parallel()
	for name, in := range map[string]string{
		"not a plist":     `<html><body/></html>`,
		"truncated":       `<plist><dict><key>a</key>`,
		"key without val": `<plist><dict><key>a</key></dict></plist>`,
		"value as key":    `<plist><dict><string>a</string><string>b</string></dict></plist>`,
		"bad integer":     `<plist><integer>1x</integer></plist>`,
		"too deep":        `<plist>` + strings.Repeat("<array>", maxPlistDepth+2) + strings.Repeat("</array>", maxPlistDepth+2) + `</plist>`,
		"empty":           ``,
	} {
		if _, err := decodePlist(bytes.NewReader([]byte(in))); !errors.Is(err, errPlist) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAttachedDevice(t *testing.T) {
	t.Parallel()
	for out, want := range map[string]string{
		"/dev/disk8\n":             "/dev/disk8",
		"/dev/disk12\t\t\n":        "/dev/disk12",
		"/dev/disk8 \tApple_HFS\n": "/dev/disk8",
		// diskutil without the image verb: an error, exit code 0.
		`diskutil: did not recognize verb "image"; type "diskutil" for a list` + "\n": "",
		"":                    "",
		"/dev/disk8s1\n":      "",
		"/dev/disk8;rm -rf /": "",
	} {
		dev, ok := attachedDevice([]byte(out))
		if dev != want || ok != (want != "") {
			t.Errorf("attachedDevice(%q) = %q, %v", out, dev, ok)
		}
	}
}

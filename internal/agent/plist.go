package agent

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// diskRe matches a macOS whole-disk device.
var diskRe = regexp.MustCompile(`^/dev/disk[0-9]+$`)

// parseRAMDisks reads the device entries of images whose path is ram://
// from the property list of `hdiutil info -plist`.
func parseRAMDisks(plist []byte) (map[string]bool, error) {
	v, err := decodePlist(bytes.NewReader(plist))
	if err != nil {
		return nil, fmt.Errorf("hdiutil info: %w", err)
	}
	root, _ := v.(map[string]any)
	images, _ := root["images"].([]any)
	out := map[string]bool{}
	for _, im := range images {
		m, _ := im.(map[string]any)
		if path, _ := m["image-path"].(string); !strings.HasPrefix(path, "ram://") {
			continue
		}
		ents, _ := m["system-entities"].([]any)
		for _, e := range ents {
			em, _ := e.(map[string]any)
			if dev, _ := em["dev-entry"].(string); diskRe.MatchString(dev) {
				out[dev] = true
			}
		}
	}
	return out, nil
}

var errPlist = errors.New("malformed property list")

// maxPlistDepth bounds nesting in decodePlist.
const maxPlistDepth = 32

// decodePlist decodes an XML property list into maps, slices, strings,
// int64s, and bools; other values decode as nil.
func decodePlist(r io.Reader) (any, error) {
	d := xml.NewDecoder(r)
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errPlist, err)
		}
		if se, ok := tok.(xml.StartElement); ok {
			if se.Name.Local != "plist" {
				return nil, fmt.Errorf("%w: root element %s", errPlist, se.Name.Local)
			}
			return plistValue(d, 0)
		}
	}
}

// plistValue reads the next value element, after skipping whitespace.
func plistValue(d *xml.Decoder, depth int) (any, error) {
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errPlist, err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return plistElement(d, t, depth)
		case xml.EndElement:
			return nil, errEndOfContainer
		}
	}
}

var errEndOfContainer = errors.New("end of container")

func plistElement(d *xml.Decoder, se xml.StartElement, depth int) (any, error) {
	if depth > maxPlistDepth {
		return nil, fmt.Errorf("%w: nested too deep", errPlist)
	}
	switch se.Name.Local {
	case "dict":
		m := map[string]any{}
		for {
			k, err := plistValue(d, depth+1)
			if errors.Is(err, errEndOfContainer) {
				return m, nil
			}
			if err != nil {
				return nil, err
			}
			key, ok := k.(plistKey)
			if !ok {
				return nil, fmt.Errorf("%w: dict entry without a key", errPlist)
			}
			v, err := plistValue(d, depth+1)
			if err != nil {
				return nil, fmt.Errorf("%w: key %q without a value", errPlist, string(key))
			}
			m[string(key)] = v
		}
	case "array":
		var a []any
		for {
			v, err := plistValue(d, depth+1)
			if errors.Is(err, errEndOfContainer) {
				return a, nil
			}
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
	case "true", "false":
		if err := d.Skip(); err != nil {
			return nil, fmt.Errorf("%w: %w", errPlist, err)
		}
		return se.Name.Local == "true", nil
	}
	var text struct {
		Value string `xml:",chardata"`
	}
	if err := d.DecodeElement(&text, &se); err != nil {
		return nil, fmt.Errorf("%w: %w", errPlist, err)
	}
	s := strings.TrimSpace(text.Value)
	switch se.Name.Local {
	case "key":
		return plistKey(s), nil
	case "string":
		return text.Value, nil
	case "integer":
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: integer %q", errPlist, s)
		}
		return n, nil
	}
	return nil, nil
}

// plistKey is a dict key, kept apart from string values.
type plistKey string

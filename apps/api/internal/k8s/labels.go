package k8s

import "strings"

// Kubernetes label syntax (K8N-4 slice B). One implementation for the gateway's Service report and for a
// namespace rule's selector.

// ValidLabelKey reports whether key is a Kubernetes label key: an optional DNS-subdomain prefix and "/",
// then a name of at most 63 characters.
func ValidLabelKey(key string) bool {
	if len(key) == 0 || len(key) > 317 { // 253-byte prefix, "/", 63-byte name
		return false
	}
	name := key
	if i := strings.LastIndexByte(key, '/'); i >= 0 {
		prefix := key[:i]
		name = key[i+1:]
		if len(prefix) == 0 || len(prefix) > 253 {
			return false
		}
		for _, part := range strings.Split(prefix, ".") {
			if !validLabelPart(part, false) {
				return false
			}
		}
	}
	return validLabelPart(name, true)
}

// ValidLabelValue reports whether value is a Kubernetes label value; empty is valid.
func ValidLabelValue(value string) bool {
	return value == "" || validLabelPart(value, true)
}

// validLabelPart: 1-63 characters, alphanumeric at both ends. A name or value may hold upper case, "_"
// and "." inside; a prefix part is a lowercase DNS label.
func validLabelPart(part string, nameSyntax bool) bool {
	if len(part) == 0 || len(part) > 63 {
		return false
	}
	alnum := func(c byte) bool {
		return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (nameSyntax && c >= 'A' && c <= 'Z')
	}
	if !alnum(part[0]) || !alnum(part[len(part)-1]) {
		return false
	}
	for i := 1; i < len(part)-1; i++ {
		c := part[i]
		if !alnum(c) && c != '-' && !(nameSyntax && (c == '_' || c == '.')) {
			return false
		}
	}
	return true
}

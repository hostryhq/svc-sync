package hub

import "encoding/base64"

func encodeB64(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }
func decodeB64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

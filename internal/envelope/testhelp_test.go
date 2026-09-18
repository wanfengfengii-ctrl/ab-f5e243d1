package envelope

import "encoding/base64"

func stdB64(b []byte) string          { return base64.StdEncoding.EncodeToString(b) }
func decB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

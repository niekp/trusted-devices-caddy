package trusteddevices

import (
	"bytes"
	"encoding/json"
	"time"
)

// tokenInfo is what the tokens file keeps per token. Without pairing only the expiry is set, and it's written as a
// plain timestamp, the format from before pairing existed.
type tokenInfo struct {
	Expires  time.Time `json:"expires"`
	Name     string    `json:"name,omitempty"`
	Created  time.Time `json:"created,omitzero"`
	LastSeen time.Time `json:"last_seen,omitzero"`
}

func (t tokenInfo) MarshalJSON() ([]byte, error) {
	if t.Name == "" && t.Created.IsZero() && t.LastSeen.IsZero() {
		return json.Marshal(t.Expires)
	}
	type plain tokenInfo
	return json.Marshal(plain(t))
}

func (t *tokenInfo) UnmarshalJSON(data []byte) error {
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte(`"`)) {
		*t = tokenInfo{}
		return json.Unmarshal(data, &t.Expires)
	}
	type plain tokenInfo
	return json.Unmarshal(data, (*plain)(t))
}

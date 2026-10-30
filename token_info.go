package trusteddevices

import (
	"bytes"
	"encoding/json"
	"time"
)

// tokenInfo is what the tokens file keeps per token. A token issued without pairing has only an expiry, and is
// written as a plain timestamp, the format from before pairing existed. A paired token is written as an object.
type tokenInfo struct {
	Expires time.Time
	// Paired marks a token approved through pairing; only those are valid where pairing is on, so a token another
	// site handed out for the same tokens file without pairing doesn't get around it.
	Paired   bool
	Name     string
	Created  time.Time
	LastSeen time.Time
}

// pairedJSON is the object form of a paired token.
type pairedJSON struct {
	Expires  time.Time  `json:"expires"`
	Paired   bool       `json:"paired"`
	Name     string     `json:"name,omitempty"`
	Created  *time.Time `json:"created,omitempty"`
	LastSeen *time.Time `json:"last_seen,omitempty"`
}

func (t tokenInfo) MarshalJSON() ([]byte, error) {
	if !t.Paired {
		return json.Marshal(t.Expires)
	}
	v := pairedJSON{Expires: t.Expires, Paired: true, Name: t.Name}
	if !t.Created.IsZero() {
		v.Created = &t.Created
	}
	if !t.LastSeen.IsZero() {
		v.LastSeen = &t.LastSeen
	}
	return json.Marshal(v)
}

func (t *tokenInfo) UnmarshalJSON(data []byte) error {
	*t = tokenInfo{}
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte(`"`)) {
		return json.Unmarshal(data, &t.Expires)
	}
	var v pairedJSON
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	t.Expires, t.Paired, t.Name = v.Expires, v.Paired, v.Name
	if v.Created != nil {
		t.Created = *v.Created
	}
	if v.LastSeen != nil {
		t.LastSeen = *v.LastSeen
	}
	return nil
}

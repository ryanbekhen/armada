package spec

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestSecretSource(t *testing.T) {
	for _, c := range []struct{ app, ref, id, key string }{
		{"api", "db-pass", "api", "db-pass"},
		{"api", "db/url", "db", "url"},
		{"api.shop", "db/URL", "db.shop", "URL"},
		{"api.shop", "JWT_SECRET", "api.shop", "JWT_SECRET"},
	} {
		id, key := SecretSource(c.app, c.ref)
		if id != c.id || key != c.key {
			t.Errorf("SecretSource(%q, %q) = %q, %q; want %q, %q", c.app, c.ref, id, key, c.id, c.key)
		}
	}
}

func TestValidateSecretKeyAndRef(t *testing.T) {
	for _, k := range []string{"db-pass", "DATABASE_URL", "jwt_secret", "_X", "a1"} {
		if err := ValidateSecretKey(k); err != nil {
			t.Errorf("key %q: %v", k, err)
		}
	}
	for _, k := range []string{"", "-a", "a-", "a.b", "a b", "a/b", "1X_", strings.Repeat("a", 64)} {
		if err := ValidateSecretKey(k); err == nil {
			t.Errorf("key %q accepted", k)
		}
	}
	for _, r := range []string{"db-pass", "db/URL", "my-db/database-url"} {
		if err := ValidateSecretRef(r); err != nil {
			t.Errorf("ref %q: %v", r, err)
		}
	}
	for _, r := range []string{"/x", "db/", "a/b/c", "DB/x", "db_x/y"} {
		if err := ValidateSecretRef(r); err == nil {
			t.Errorf("ref %q accepted", r)
		}
	}
}

func TestSecretEnvName(t *testing.T) {
	for in, want := range map[string]string{
		"database-url": "DATABASE_URL", "db1": "DB1", "DATABASE_URL": "DATABASE_URL", "jwt_secret": "jwt_secret",
	} {
		if got := SecretEnvName(in); got != want {
			t.Errorf("SecretEnvName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestEnvFromForms checks both forms of envFrom, and that the old form is
// stored and exported as the same bytes as before ADR 0052.
func TestEnvFromForms(t *testing.T) {
	old, err := Parse([]byte("name: api\nimage: nginx:1\nenvFrom: secrets\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !old.EnvFrom.Own || old.UsesSpaceSecrets() {
		t.Errorf("envFrom: secrets = %+v, space secrets %v", old.EnvFrom, old.UsesSpaceSecrets())
	}
	b, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"envFrom":"secrets"`) {
		t.Errorf("JSON of the old form: %s", b)
	}
	var back App
	if err := json.Unmarshal(b, &back); err != nil || !back.EnvFrom.Own {
		t.Errorf("JSON round trip: %+v %v", back.EnvFrom, err)
	}
	if out, _ := old.Export(); !strings.Contains(string(out), "envFrom: secrets\n") {
		t.Errorf("export of the old form:\n%s", out)
	}

	none, _ := Parse([]byte("name: api\nimage: nginx:1\n"))
	if b, _ := json.Marshal(none); strings.Contains(string(b), "envFrom") {
		t.Errorf("JSON without envFrom: %s", b)
	}
	if out, _ := none.Export(); strings.Contains(string(out), "envFrom") {
		t.Errorf("export without envFrom:\n%s", out)
	}

	list, err := Parse([]byte("name: api\nimage: nginx:1\nenvFrom:\n  - secret: db\n  - secret: mail\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !list.UsesSpaceSecrets() || len(list.EnvFrom.Secrets) != 2 || list.EnvFrom.Secrets[1].Secret != "mail" {
		t.Errorf("list form: %+v", list.EnvFrom)
	}
	b, _ = json.Marshal(list)
	back = App{}
	if err := json.Unmarshal(b, &back); err != nil || len(back.EnvFrom.Secrets) != 2 {
		t.Errorf("JSON round trip of the list: %s %+v %v", b, back.EnvFrom, err)
	}
	out, _ := list.Export()
	again, err := Parse(out)
	if err != nil || len(again.EnvFrom.Secrets) != 2 {
		t.Errorf("export of the list does not parse back:\n%s\n%v", out, err)
	}

	ref, _ := Parse([]byte("name: api\nimage: nginx:1\nenv:\n  - name: DB\n    secretRef: db/url\n"))
	if ref == nil || !ref.UsesSpaceSecrets() {
		t.Error("a SECRET/KEY reference does not count as using space secrets")
	}
}

func TestWithSecretEnvList(t *testing.T) {
	a, err := Parse([]byte(`name: api
image: nginx:1
env:
  - name: LOG_LEVEL
    value: debug
envFrom:
  - secret: db
  - secret: mail
secretFiles:
  - secretRef: db/tls-key
    path: /run/tls.key
`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.WithSecretEnv(map[string][]string{
		"":     {"ignored"},
		"db":   {"DATABASE_URL", "tls-key", "LOG_LEVEL", "pool-size"},
		"mail": {"DATABASE_URL", "SMTP_HOST", "PORT"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var vars []string
	for _, e := range got.Env {
		vars = append(vars, e.Name+"="+e.SecretRef)
	}
	want := []string{"LOG_LEVEL=", "DATABASE_URL=db/DATABASE_URL", "POOL_SIZE=db/pool-size", "SMTP_HOST=mail/SMTP_HOST"}
	if !slices.Equal(vars, want) {
		t.Errorf("env = %v\nwant %v", vars, want)
	}
	if !slices.Equal(got.EnvFromAdded, []string{"DATABASE_URL", "POOL_SIZE", "SMTP_HOST"}) {
		t.Errorf("added = %v", got.EnvFromAdded)
	}
}

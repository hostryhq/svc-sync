package realdir

import (
	"errors"
	"net/url"
	"strings"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/svc-sync/identityclient"
	"github.com/hostryhq/svc-sync/tenancyclient"
)

// FromEnv builds the directory from the environment, failing fast with every problem at once:
//
//	SYNC_IDENTITY_URL                base URL of the identity service (https outside development)
//	SYNC_TENANCY_URL                 base URL of the tenancy service
//	SYNC_SERVICE_SIGNING_KEY_FILE    PEM PKCS#8 P-256 private key of sync's service tokens (a file reference; never a value)
//	SYNC_DIRECTORY_STATE_FILE        optional file that persists the revocation cursor and set
func FromEnv(getenv func(string) string) (*Directory, error) {
	var problems []string
	check := func(name string) string {
		v := getenv(name)
		if u, err := url.Parse(v); v == "" || err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			problems = append(problems, name+" must be an http(s) URL")
		}
		return v
	}
	idURL, tenURL := check("SYNC_IDENTITY_URL"), check("SYNC_TENANCY_URL")
	keyFile := getenv("SYNC_SERVICE_SIGNING_KEY_FILE")
	var signer *auth.ServiceSigner
	if keyFile == "" {
		problems = append(problems, "SYNC_SERVICE_SIGNING_KEY_FILE is required")
	} else if k, err := identityclient.ReadKey(keyFile); err != nil {
		problems = append(problems, "SYNC_SERVICE_SIGNING_KEY_FILE: "+err.Error())
	} else {
		signer = &auth.ServiceSigner{Name: identityclient.ServiceName, Key: k}
	}
	if len(problems) > 0 {
		return nil, errors.New("identity directory: " + strings.Join(problems, "; "))
	}
	ic, err := identityclient.New(idURL, signer, nil)
	if err != nil {
		return nil, err
	}
	tc, err := tenancyclient.New(tenURL, signer, nil)
	if err != nil {
		return nil, err
	}
	return &Directory{Identity: ic, Tenancy: tc, StateFile: getenv("SYNC_DIRECTORY_STATE_FILE")}, nil
}

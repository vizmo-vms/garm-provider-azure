//    Licensed under the Apache License, Version 2.0 (the "License"); you may
//    not use this file except in compliance with the License. You may obtain
//    a copy of the License at
//
//         http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
//    License for the specific language governing permissions and limitations
//    under the License.

package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/stretchr/testify/require"
)

// writeTestCertificate writes a self-signed certificate and its RSA key to a
// PEM file, the format "az ad sp create-for-rbac --create-cert" produces.
func writeTestCertificate(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "garm-provider-azure-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	path := filepath.Join(t.TempDir(), "sp.pem")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func TestServicePrincipalCertificate(t *testing.T) {
	certPath := writeTestCertificate(t)

	sp := ServicePrincipalCredentials{
		TenantID:              "tenantID",
		ClientID:              "clientID",
		ClientCertificatePath: certPath,
	}
	require.NoError(t, sp.Validate())
	cred, err := sp.Auth(azcore.ClientOptions{})
	require.NoError(t, err)
	require.NotNil(t, cred)

	creds := Credentials{SubscriptionID: "subscriptionID", SPCredentials: sp}
	require.NoError(t, creds.Validate())
}

func TestServicePrincipalCredentialChoice(t *testing.T) {
	certPath := writeTestCertificate(t)

	tests := []struct {
		name      string
		sp        ServicePrincipalCredentials
		errString string
	}{
		{
			name:      "secret only",
			sp:        ServicePrincipalCredentials{TenantID: "tenantID", ClientID: "clientID", ClientSecret: "clientSecret"},
			errString: "",
		},
		{
			name:      "neither secret nor certificate",
			sp:        ServicePrincipalCredentials{TenantID: "tenantID", ClientID: "clientID"},
			errString: "missing client_secret or client_certificate_path",
		},
		{
			name:      "both secret and certificate",
			sp:        ServicePrincipalCredentials{TenantID: "tenantID", ClientID: "clientID", ClientSecret: "clientSecret", ClientCertificatePath: certPath},
			errString: "client_secret and client_certificate_path are mutually exclusive",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.sp.Validate()
			if tc.errString == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.errString)
			}
		})
	}
}

func TestServicePrincipalCertificateErrorsAreReported(t *testing.T) {
	badPEM := filepath.Join(t.TempDir(), "bad.pem")
	require.NoError(t, os.WriteFile(badPEM, []byte("not a certificate"), 0o600))

	for name, path := range map[string]string{
		"missing file": filepath.Join(t.TempDir(), "absent.pem"),
		"invalid PEM":  badPEM,
	} {
		t.Run(name, func(t *testing.T) {
			creds := Credentials{
				SubscriptionID: "subscriptionID",
				SPCredentials: ServicePrincipalCredentials{
					TenantID:              "tenantID",
					ClientID:              "clientID",
					ClientCertificatePath: path,
				},
			}
			_, err := creds.GetCredentials()
			require.ErrorContains(t, err, "service principal certificate")
		})
	}
}

package provider

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

const (
	busyboxImage = "busybox:1.36"
	agnhostImage = "registry.k8s.io/e2e-test-images/agnhost:2.43"
)

var (
	testAccProvider          *schema.Provider
	testAccExternalProviders map[string]resource.ExternalProvider
	testAccProviderFactories = map[string]func() (*schema.Provider, error){
		"jwks": func() (*schema.Provider, error) {
			return Provider(), nil
		},
	}
)

func init() {
	testAccProvider = Provider()
	testAccProviderFactories = map[string]func() (*schema.Provider, error){
		"jwks": func() (*schema.Provider, error) {
			return Provider(), nil
		},
	}
	testAccExternalProviders = map[string]resource.ExternalProvider{
		"aws": {
			Source: "hashicorp/aws",
		},
		"google": {
			Source: "hashicorp/google",
		},
		"azurerm": {
			Source: "hashicorp/azurerm",
		},
	}
}

func TestProvider(t *testing.T) {
	provider := Provider()
	if err := provider.InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestProvider_impl(t *testing.T) {
	var _ schema.Provider = *Provider()
}

func TestProvider_configure_path(t *testing.T) {
	ctx := context.TODO()
	resetEnv := unsetEnv(t)
	defer resetEnv()

	os.Setenv("KUBE_CONFIG_PATH", "test-fixtures/kube-config.yaml")
	os.Setenv("KUBE_CTX", "gcp")

	rc := terraform.NewResourceConfigRaw(map[string]interface{}{})
	p := Provider()
	diags := p.Configure(ctx, rc)
	if diags.HasError() {
		t.Fatal(diags)
	}
}

func TestProvider_configure_paths(t *testing.T) {
	ctx := context.TODO()
	resetEnv := unsetEnv(t)
	defer resetEnv()

	os.Setenv("KUBE_CONFIG_PATHS", strings.Join([]string{
		"test-fixtures/kube-config.yaml",
		"test-fixtures/kube-config-secondary.yaml",
	}, string(os.PathListSeparator)))
	os.Setenv("KUBE_CTX", "oidc")

	rc := terraform.NewResourceConfigRaw(map[string]interface{}{})
	p := Provider()
	diags := p.Configure(ctx, rc)
	if diags.HasError() {
		t.Fatal(diags)
	}
}

func unsetEnv(t *testing.T) func() {
	e := getEnv()

	envVars := map[string]string{
		"KUBE_CONFIG_PATH":          e.ConfigPath,
		"KUBE_CONFIG_PATHS":         strings.Join(e.ConfigPaths, string(os.PathListSeparator)),
		"KUBE_CTX":                  e.Ctx,
		"KUBE_CTX_AUTH_INFO":        e.CtxAuthInfo,
		"KUBE_CTX_CLUSTER":          e.CtxCluster,
		"KUBE_HOST":                 e.Host,
		"KUBE_USER":                 e.User,
		"KUBE_PASSWORD":             e.Password,
		"KUBE_CLIENT_CERT_DATA":     e.ClientCertData,
		"KUBE_CLIENT_KEY_DATA":      e.ClientKeyData,
		"KUBE_CLUSTER_CA_CERT_DATA": e.ClusterCACertData,
		"KUBE_INSECURE":             e.Insecure,
		"KUBE_TLS_SERVER_NAME":      e.TLSServerName,
		"KUBE_TOKEN":                e.Token,
	}

	for k := range envVars {
		if err := os.Unsetenv(k); err != nil {
			t.Fatalf("Error unsetting env var %s: %s", k, err)
		}
	}

	return func() {
		for k, v := range envVars {
			if err := os.Setenv(k, v); err != nil {
				t.Fatalf("Error resetting env var %s: %s", k, err)
			}
		}
	}
}

func getEnv() *currentEnv {
	e := &currentEnv{
		Ctx:               os.Getenv("KUBE_CTX"),
		CtxAuthInfo:       os.Getenv("KUBE_CTX_AUTH_INFO"),
		CtxCluster:        os.Getenv("KUBE_CTX_CLUSTER"),
		Host:              os.Getenv("KUBE_HOST"),
		User:              os.Getenv("KUBE_USER"),
		Password:          os.Getenv("KUBE_PASSWORD"),
		ClientCertData:    os.Getenv("KUBE_CLIENT_CERT_DATA"),
		ClientKeyData:     os.Getenv("KUBE_CLIENT_KEY_DATA"),
		ClusterCACertData: os.Getenv("KUBE_CLUSTER_CA_CERT_DATA"),
		Insecure:          os.Getenv("KUBE_INSECURE"),
		TLSServerName:     os.Getenv("KUBE_TLS_SERVER_NAME"),
		Token:             os.Getenv("KUBE_TOKEN"),
	}
	if v := os.Getenv("KUBE_CONFIG_PATH"); v != "" {
		e.ConfigPath = v
	}
	if v := os.Getenv("KUBE_CONFIG_PATH"); v != "" {
		e.ConfigPaths = filepath.SplitList(v)
	}
	return e
}

func testAccPreCheck(t *testing.T) {
	ctx := context.TODO()
	hasFileCfg := (os.Getenv("KUBE_CTX_AUTH_INFO") != "" && os.Getenv("KUBE_CTX_CLUSTER") != "") ||
		os.Getenv("KUBE_CTX") != "" ||
		os.Getenv("KUBE_CONFIG_PATH") != ""
	hasUserCredentials := os.Getenv("KUBE_USER") != "" && os.Getenv("KUBE_PASSWORD") != ""
	hasClientCert := os.Getenv("KUBE_CLIENT_CERT_DATA") != "" && os.Getenv("KUBE_CLIENT_KEY_DATA") != ""
	hasStaticCfg := (os.Getenv("KUBE_HOST") != "" &&
		os.Getenv("KUBE_CLUSTER_CA_CERT_DATA") != "") &&
		(hasUserCredentials || hasClientCert || os.Getenv("KUBE_TOKEN") != "")

	if !hasFileCfg && !hasStaticCfg && !hasUserCredentials {
		t.Fatalf("File config (KUBE_CTX_AUTH_INFO and KUBE_CTX_CLUSTER) or static configuration"+
			"(%s) or (%s) must be set for acceptance tests",
			strings.Join([]string{
				"KUBE_HOST",
				"KUBE_USER",
				"KUBE_PASSWORD",
				"KUBE_CLUSTER_CA_CERT_DATA",
			}, ", "),
			strings.Join([]string{
				"KUBE_HOST",
				"KUBE_CLIENT_CERT_DATA",
				"KUBE_CLIENT_KEY_DATA",
				"KUBE_CLUSTER_CA_CERT_DATA",
			}, ", "),
		)
	}

	diags := testAccProvider.Configure(ctx, terraform.NewResourceConfigRaw(nil))
	if diags.HasError() {
		t.Fatal(diags[0].Summary)
	}
}

type currentEnv struct {
	ConfigPath        string
	ConfigPaths       []string
	Ctx               string
	CtxAuthInfo       string
	CtxCluster        string
	Host              string
	User              string
	Password          string
	ClientCertData    string
	ClientKeyData     string
	ClusterCACertData string
	Insecure          string
	TLSServerName     string
	Token             string
}

package provider

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceJWKS() *schema.Resource {
	return &schema.Resource{
		Description: "Data source to retrieve JSON Web Key Set (JWKS) from a Kubernetes cluster.",
		ReadContext: dataSourceJWKSRead,
		Schema: map[string]*schema.Schema{
			"jwks": {
				Type:        schema.TypeString,
				Description: "JSON Web Key Set (JWKS) retrieved from the Kubernetes cluster.",
				Computed:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func dataSourceJWKSRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn, err := meta.(KubeClientsets).MainClientset()
	if err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[INFO] Getting JWKS from Kubernetes cluster")

	jwksRaw, err := conn.CoreV1().RESTClient().Get().RequestURI("/openid/v1/jwks").DoRaw(ctx)
	if err != nil {
		log.Printf("[DEBUG] Received error: %#v", err)
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] JWKS Raw: %s", string(jwksRaw))

	err = d.Set("jwks", string(jwksRaw))
	if err != nil {
		return diag.FromErr(err)
	}

	idsum := sha256.New()
	_, err = idsum.Write(jwksRaw)
	if err != nil {
		return diag.FromErr(err)
	}

	id := fmt.Sprintf("%x", idsum.Sum(nil))
	d.SetId(id)

	return nil
}

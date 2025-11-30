package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccJwksDataSource_basic(t *testing.T) {
	// dataSourceName := "data.jwks.test"
	// rxPosNum := regexp.MustCompile("^[1-9][0-9]*$")
	// nsName := regexp.MustCompile(`^[a-zA-Z][-\w]*$`)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKubernetesDataSourceAllNamespacesConfig_basic(),
				Check:  resource.ComposeAggregateTestCheckFunc(
				// resource.TestMatchResourceAttr(dataSourceName, "jwks.#", rxPosNum),
				// resource.TestCheckResourceAttrSet(dataSourceName, "namespaces.0"),
				// resource.TestMatchResourceAttr(dataSourceName, "namespaces.0", nsName),
				),
			},
		},
	})
}

func testAccKubernetesDataSourceAllNamespacesConfig_basic() string {
	return `data "jwks" "test" {}`
}

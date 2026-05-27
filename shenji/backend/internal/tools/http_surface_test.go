package tools

import "testing"

func TestHTTPSurfaceExtractsImageMapAreaLinks(t *testing.T) {
	body := `<map name="fm_imagemap"><area shape="rect" href="Less-1" alt="Less-1" /></map>`
	result := discoverHTTPSurface("http://target/", body)
	if len(result.Links) != 1 || result.Links[0].URL != "http://target/Less-1" {
		t.Fatalf("expected image-map area href to be discovered, got %+v", result.Links)
	}
}

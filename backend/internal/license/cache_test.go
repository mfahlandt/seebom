package license

import "testing"

func TestResolverCacheStoreResult(t *testing.T) {
	var c ResolverCache
	c.StoreResult("lic", "MIT", "")
	c.StoreResult("neg", "", ReasonNotPublished)
	c.StoreResult("transient", "", "")
	c.PreloadCache(map[string]string{"legacy": "", "pre": "!" + ReasonNoLicenseUpstream})

	if lic, _, ok := c.Load("lic"); !ok || lic != "MIT" {
		t.Errorf("license not cached: %q %v", lic, ok)
	}
	if lic, reason, ok := c.Load("neg"); !ok || lic != "" || reason != ReasonNotPublished {
		t.Errorf("negative with reason not cached: %q %q %v", lic, reason, ok)
	}
	if _, ok := c.LoadValue("transient"); ok {
		t.Error("negative without reason must not be cached")
	}
	if _, ok := c.LoadValue("legacy"); ok {
		t.Error("preloaded empty value must be skipped")
	}
	if c.Reason("pre") != ReasonNoLicenseUpstream {
		t.Errorf("Reason(pre) = %q", c.Reason("pre"))
	}
	if got := c.CacheEntries(); len(got) != 3 || got["neg"] != "!"+ReasonNotPublished {
		t.Errorf("CacheEntries = %v", got)
	}
}

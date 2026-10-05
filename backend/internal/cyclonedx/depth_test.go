package cyclonedx

import (
	"reflect"
	"testing"
)

// The product of a CycloneDX document lives in metadata.component, outside the
// components array. Its dependsOn entry therefore cannot become a relationship
// row (there is no source index) and instead seeds the depth-1 set.
func TestParse_RootDependsOnSeedsDirectIndices(t *testing.T) {
	cdxJSON := []byte(`{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
		"metadata": {"component": {"type": "application", "bom-ref": "app", "name": "my-app", "version": "1.0.0"}},
		"components": [
			{"type": "library", "bom-ref": "a", "name": "a", "version": "1"},
			{"type": "library", "bom-ref": "b", "name": "b", "version": "1"},
			{"type": "library", "bom-ref": "c", "name": "c", "version": "1"}
		],
		"dependencies": [
			{"ref": "app", "dependsOn": ["a", "b", "missing"]},
			{"ref": "a", "dependsOn": ["c"]}
		]
	}`)

	res, err := Parse(cdxJSON, "t.cdx.json", "h")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := res.Packages.DirectIndices, []uint32{0, 1}; !reflect.DeepEqual(got, want) {
		t.Errorf("DirectIndices = %v, want %v (unknown refs dropped)", got, want)
	}
	// Only a→c is a relationship between array members.
	if got, want := res.Packages.RelSourceIndices, []uint32{0}; !reflect.DeepEqual(got, want) {
		t.Errorf("RelSourceIndices = %v, want %v", got, want)
	}
	if got, want := res.Packages.RelTargetIndices, []uint32{2}; !reflect.DeepEqual(got, want) {
		t.Errorf("RelTargetIndices = %v, want %v", got, want)
	}
}

// Some generators repeat the product inside the components array. Then it has
// an index, its dependsOn are ordinary relationships, and nothing is seeded –
// depth derives from the graph itself.
func TestParse_RootInsideComponentsIsOrdinaryRelationship(t *testing.T) {
	cdxJSON := []byte(`{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
		"metadata": {"component": {"type": "application", "bom-ref": "app", "name": "my-app", "version": "1.0.0"}},
		"components": [
			{"type": "application", "bom-ref": "app", "name": "my-app", "version": "1.0.0"},
			{"type": "library", "bom-ref": "a", "name": "a", "version": "1"}
		],
		"dependencies": [{"ref": "app", "dependsOn": ["a"]}]
	}`)

	res, err := Parse(cdxJSON, "t.cdx.json", "h")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages.DirectIndices) != 0 {
		t.Errorf("DirectIndices = %v, want none", res.Packages.DirectIndices)
	}
	if got, want := res.Packages.RelSourceIndices, []uint32{0}; !reflect.DeepEqual(got, want) {
		t.Errorf("RelSourceIndices = %v, want %v", got, want)
	}
}

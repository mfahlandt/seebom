package dto

import "testing"

func TestSeverityCountsAdd(t *testing.T) {
	var c SeverityCounts
	c.Add("CRITICAL", 2)
	c.Add("HIGH", 3)
	c.Add("MEDIUM", 4)
	c.Add("LOW", 5)
	c.Add("UNKNOWN", 6) // counted in total only
	want := SeverityCounts{Total: 20, Critical: 2, High: 3, Medium: 4, Low: 5}
	if c != want {
		t.Fatalf("got %+v, want %+v", c, want)
	}
}

package main

import (
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// #332: explicit upload headers must outrank document extraction — per field,
// not as a pair.

func TestSourceOverride(t *testing.T) {
	tests := []struct {
		name              string
		docRepo, docRef   string
		jobRepo, jobRef   string
		wantRepo, wantRef string
	}{
		{
			name:    "no override keeps document values",
			docRepo: "https://github.com/doc/repo", docRef: "v1.0.0",
			wantRepo: "https://github.com/doc/repo", wantRef: "v1.0.0",
		},
		{
			name:    "full override replaces both",
			docRepo: "https://github.com/doc/repo", docRef: "v1.0.0",
			jobRepo: "https://github.com/real/repo", jobRef: "abc1234",
			wantRepo: "https://github.com/real/repo", wantRef: "abc1234",
		},
		{
			name:    "repo-only override keeps the document ref",
			docRepo: "https://github.com/doc/repo", docRef: "v1.0.0",
			jobRepo:  "https://github.com/real/repo",
			wantRepo: "https://github.com/real/repo", wantRef: "v1.0.0",
		},
		{
			name:     "ref-only override keeps the document repo",
			docRepo:  "https://github.com/doc/repo",
			jobRef:   "deadbeef",
			wantRepo: "https://github.com/doc/repo", wantRef: "deadbeef",
		},
		{
			name:    "override fills in when the document has nothing",
			jobRepo: "https://github.com/real/repo", jobRef: "main",
			wantRepo: "https://github.com/real/repo", wantRef: "main",
		},
		{
			name: "nothing anywhere stays empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbom := models.SBOM{SourceRepo: tt.docRepo, SourceRef: tt.docRef}
			job := models.IngestionJob{SourceRepo: tt.jobRepo, SourceRef: tt.jobRef}

			applySourceOverride(&sbom, job)

			if sbom.SourceRepo != tt.wantRepo || sbom.SourceRef != tt.wantRef {
				t.Errorf("got (%q, %q), want (%q, %q)",
					sbom.SourceRepo, sbom.SourceRef, tt.wantRepo, tt.wantRef)
			}
		})
	}
}

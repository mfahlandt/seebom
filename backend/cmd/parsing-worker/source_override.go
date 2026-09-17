package main

import (
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// applySourceOverride resolves source_repo/source_ref (#332) between the two
// places a value can come from:
//
//   - the job: an explicit X-Source-Repo/X-Source-Ref upload header, already
//     validated and normalised by the gateway;
//   - the SBOM: what the parser extracted from the document itself.
//
// The job wins per field, not as a pair: a CI pipeline that states the repo
// but not the ref should still keep a ref the document carries — repo and ref
// are independently knowable, and discarding a valid document ref because the
// caller only knew the repo would throw information away.
//
// The parser value is only a fallback, never merged the other way: an
// explicit header is an authenticated caller's statement of fact, and a
// document that disagrees (e.g. a stale template) must not override it.
func applySourceOverride(sbom *models.SBOM, job models.IngestionJob) {
	if job.SourceRepo != "" {
		sbom.SourceRepo = job.SourceRepo
	}
	if job.SourceRef != "" {
		sbom.SourceRef = job.SourceRef
	}
}

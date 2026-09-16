package main

import (
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// ownership carries the three orthogonal dimensions (#131 cluster, #138
// namespace, #57 project) from an ingestion job onto the rows produced for it.
//
// This exists so the copy happens in one place instead of six. Each data table
// is written by a different part of processSBOMJob, and a single forgotten
// assignment produces rows that are silently DEFAULT ” — indistinguishable
// from "genuinely unassigned" and only fixable by re-ingesting. Centralising it
// makes that class of bug a compile-or-test failure rather than a data one.
type ownership struct {
	cluster   string
	namespace string
	project   string
}

// ownershipOf reads the dimensions assigned to a job by the ingestion watcher
// (or the upload endpoint).
func ownershipOf(job models.IngestionJob) ownership {
	return ownership{
		cluster:   job.Cluster,
		namespace: job.Namespace,
		project:   job.Project,
	}
}

func (o ownership) applySBOM(m *models.SBOM) {
	m.Cluster, m.Namespace, m.Project = o.cluster, o.namespace, o.project
}

func (o ownership) applyPackages(m *models.SBOMPackages) {
	m.Cluster, m.Namespace, m.Project = o.cluster, o.namespace, o.project
}

func (o ownership) applyVulnerability(m *models.Vulnerability) {
	m.Cluster, m.Namespace, m.Project = o.cluster, o.namespace, o.project
}

func (o ownership) applyLicenseCompliance(m *models.LicenseCompliance) {
	m.Cluster, m.Namespace, m.Project = o.cluster, o.namespace, o.project
}

func (o ownership) applyStoredDocument(m *models.StoredDocument) {
	m.Cluster, m.Namespace, m.Project = o.cluster, o.namespace, o.project
}

// applyVEXStatements stamps every statement in a parsed VEX document.
// The VEX parser only sees the document, never the job, so without this the
// rows land unattributed — which is exactly what happened to `cluster` between
// #131 and #138.
func (o ownership) applyVEXStatements(stmts []models.VEXStatement) {
	for i := range stmts {
		o.applyVEXStatement(&stmts[i])
	}
}

func (o ownership) applyVEXStatement(m *models.VEXStatement) {
	m.Cluster, m.Namespace, m.Project = o.cluster, o.namespace, o.project
}

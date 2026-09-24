package main

import (
	"errors"
	"log"
	"net/http"
	"os"

	"github.com/seebom-labs/bomhort/backend/internal/license"
)

// applyLicenseExpressionMode applies the LICENSE_EXPRESSION_MODE override on
// top of whatever LoadPolicy installed. Empty means "defer to the policy
// file"; an invalid value is a startup error so a typo never silently falls
// back to strict on one component and permissive-wins on another.
func applyLicenseExpressionMode(raw string) {
	if raw != "" {
		mode, err := license.ParseExpressionMode(raw)
		if err != nil {
			log.Fatalf("Invalid LICENSE_EXPRESSION_MODE: %v", err)
		}
		license.SetExpressionMode(mode)
	}
	log.Printf("License expression mode: %s", license.GetExpressionMode())
}

func loadRequestExceptions(w http.ResponseWriter, paths ...string) (*license.ExceptionIndex, bool) {
	idx, err := license.LoadExceptionsWithFallback(paths...)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("ERROR: license exceptions configuration: %v", err)
		writeError(w, http.StatusInternalServerError, "Invalid license exceptions configuration")
		return nil, false
	}
	return idx, true
}

func licenseExceptionsHandler(paths ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idx, ok := loadRequestExceptions(w, paths...)
		if !ok {
			return
		}
		if idx == nil {
			writeJSON(w, http.StatusOK, license.ExceptionsFile{
				Version:           "1.0.0",
				BlanketExceptions: []license.BlanketException{},
				Exceptions:        []license.Exception{},
			})
			return
		}
		writeJSON(w, http.StatusOK, idx.Raw)
	}
}

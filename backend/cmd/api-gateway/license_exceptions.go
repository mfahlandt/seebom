package main

import (
	"errors"
	"log"
	"net/http"
	"os"

	"github.com/seebom-labs/bomhort/backend/internal/license"
)

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

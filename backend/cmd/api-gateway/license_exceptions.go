package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/seebom-labs/bomhort/backend/internal/license"
	"github.com/seebom-labs/bomhort/backend/internal/rulesource"
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

// requestExceptions returns the exceptions a request should be answered with.
// An unreachable remote source keeps the last good rules (rulesource), but a
// document that is invalid is reported, not papered over: answering with
// rules that no longer match the reviewed file would look correct and not be.
func requestExceptions(w http.ResponseWriter, rules *license.ExceptionsWatcher) (*license.ExceptionIndex, bool) {
	s := rules.Current()
	switch {
	case errors.Is(s.Err, rulesource.ErrInvalid):
		log.Printf("ERROR: license exceptions configuration: %v", s.Err)
		writeError(w, http.StatusInternalServerError, "Invalid license exceptions configuration")
		return nil, false
	case !s.Ready:
		log.Printf("ERROR: license exceptions not loaded yet: %v", s.Err)
		writeError(w, http.StatusServiceUnavailable, "License exceptions are not available yet")
		return nil, false
	}
	return s.Value, true
}

func licenseExceptionsHandler(rules *license.ExceptionsWatcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idx, ok := requestExceptions(w, rules)
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

// watchExceptions loads the exceptions once and keeps them current. Unlike
// the worker, the gateway starts with unreadable rules: it only reports them,
// and every other endpoint keeps working.
func watchExceptions(ctx context.Context, opts rulesource.Options, interval time.Duration) (*license.ExceptionsWatcher, error) {
	rules, err := license.WatchExceptions(opts)
	if err != nil {
		return nil, err
	}
	if _, err := rules.Refresh(ctx); err != nil {
		log.Printf("ERROR: license exceptions from %s: %v", rules.Current().Source, err)
	}
	go rules.Run(ctx, interval, func(s rulesource.Snapshot[*license.ExceptionIndex]) {
		log.Printf("License exceptions reloaded from %s (%s)", s.Source, s.Digest[:12])
	})
	return rules, nil
}

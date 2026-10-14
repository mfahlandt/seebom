package config

import (
	"strings"
	"testing"
)

func TestLoad_ClickHouseQueryLimits(t *testing.T) {
	t.Run("unset by default", func(t *testing.T) {
		for _, k := range []string{"CLICKHOUSE_MAX_EXECUTION_TIME", "CLICKHOUSE_MAX_MEMORY_USAGE", "CLICKHOUSE_MAX_THREADS"} {
			t.Setenv(k, "")
		}
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.ClickHouseMaxExecutionTime != 0 || cfg.ClickHouseMaxMemoryUsage != 0 || cfg.ClickHouseMaxThreads != 0 {
			t.Errorf("limits must default to unset, got %d/%d/%d",
				cfg.ClickHouseMaxExecutionTime, cfg.ClickHouseMaxMemoryUsage, cfg.ClickHouseMaxThreads)
		}
	})

	t.Run("parsed", func(t *testing.T) {
		t.Setenv("CLICKHOUSE_MAX_EXECUTION_TIME", "30")
		t.Setenv("CLICKHOUSE_MAX_MEMORY_USAGE", " 8589934592 ")
		t.Setenv("CLICKHOUSE_MAX_THREADS", "4")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.ClickHouseMaxExecutionTime != 30 {
			t.Errorf("max execution time = %d, want 30", cfg.ClickHouseMaxExecutionTime)
		}
		if cfg.ClickHouseMaxMemoryUsage != 8<<30 {
			t.Errorf("max memory usage = %d, want 8 GiB (beyond int32)", cfg.ClickHouseMaxMemoryUsage)
		}
		if cfg.ClickHouseMaxThreads != 4 {
			t.Errorf("max threads = %d, want 4", cfg.ClickHouseMaxThreads)
		}
	})

	// A typo must not silently become "no limit".
	for env, val := range map[string]string{
		"CLICKHOUSE_MAX_EXECUTION_TIME": "30s",
		"CLICKHOUSE_MAX_MEMORY_USAGE":   "512Mi",
		"CLICKHOUSE_MAX_THREADS":        "-1",
	} {
		t.Run("rejects "+env, func(t *testing.T) {
			t.Setenv(env, val)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), env) {
				t.Fatalf("Load with %s=%q: err = %v, want an error naming the variable", env, val, err)
			}
		})
	}
}

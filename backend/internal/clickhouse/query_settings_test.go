package clickhouse

import (
	"context"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2"

	"github.com/seebom-labs/bomhort/backend/internal/config"
)

func TestQuerySettings(t *testing.T) {
	if s := querySettings(&config.Config{}); s != nil {
		t.Errorf("no limits configured: settings = %v, want nil so the server profile decides", s)
	}

	got := querySettings(&config.Config{
		ClickHouseMaxExecutionTime: 30,
		ClickHouseMaxMemoryUsage:   1 << 29,
	})
	want := clickhouse.Settings{"max_execution_time": 30, "max_memory_usage": int64(1 << 29), "max_bytes_before_external_group_by": int64(1 << 28), "max_bytes_before_external_sort": int64(1 << 28)}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("settings = %#v, want %#v (unset max_threads must be omitted, not sent as 0)", got, want)
	}
}

// TestQueryLimitsReachTheServer checks that the limits are applied by the
// server, not just put into the options: a misspelled setting name would be
// rejected here, and an ignored one would read back as the server default.
func TestQueryLimitsReachTheServer(t *testing.T) {
	testClient(t) // skips without CLICKHOUSE_HOST
	port, err := strconv.Atoi(envOr("CLICKHOUSE_PORT", "9000"))
	if err != nil {
		t.Fatalf("CLICKHOUSE_PORT: %v", err)
	}
	c, err := NewClient(&config.Config{
		ClickHouseHost:             os.Getenv("CLICKHOUSE_HOST"),
		ClickHousePort:             port,
		ClickHouseDatabase:         envOr("CLICKHOUSE_DATABASE", "bomhort"),
		ClickHouseUser:             envOr("CLICKHOUSE_USER", "default"),
		ClickHousePassword:         os.Getenv("CLICKHOUSE_PASSWORD"),
		ClickHouseMaxExecutionTime: 17,
		ClickHouseMaxMemoryUsage:   123456789,
		ClickHouseMaxThreads:       3,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	var execTime, memory, threads string
	if err := c.Conn.QueryRow(context.Background(),
		"SELECT toString(getSetting('max_execution_time')), toString(getSetting('max_memory_usage')), toString(getSetting('max_threads'))",
	).Scan(&execTime, &memory, &threads); err != nil {
		t.Fatalf("getSetting: %v", err)
	}
	if execTime != "17" || memory != "123456789" || !strings.Contains(threads, "3") {
		t.Errorf("server sees max_execution_time=%s max_memory_usage=%s max_threads=%s, want 17/123456789/3",
			execTime, memory, threads)
	}
}

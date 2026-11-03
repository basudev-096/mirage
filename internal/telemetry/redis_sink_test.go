package telemetry

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/redis/go-redis/v9"
)

type recordingStreamWriter struct {
	args *redis.XAddArgs
}

func (w *recordingStreamWriter) XAdd(_ context.Context, args *redis.XAddArgs) *redis.StringCmd {
	w.args = args
	return redis.NewStringResult("1-0", nil)
}

func TestRedisSinkSerializesEvent(t *testing.T) {
	writer := &recordingStreamWriter{}
	sink := &RedisSink{client: writer, stream: "mirage:events", maxLen: 1000}
	event := Event{SourceIP: "192.0.2.10", Verdict: "Malicious", Category: "SQLi"}

	if err := sink.Write(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if writer.args.Stream != "mirage:events" || writer.args.MaxLen != 1000 || !writer.args.Approx {
		t.Fatalf("unexpected XADD args: %+v", writer.args)
	}
	values, ok := writer.args.Values.(map[string]any)
	if !ok {
		t.Fatalf("values have type %T, want map", writer.args.Values)
	}
	encoded, ok := values["event"].(string)
	if !ok {
		t.Fatalf("event value has type %T, want string", values["event"])
	}
	var got Event
	if err := json.Unmarshal([]byte(encoded), &got); err != nil {
		t.Fatal(err)
	}
	if got.SourceIP != event.SourceIP || got.Category != event.Category {
		t.Fatalf("event = %+v, want %+v", got, event)
	}
}

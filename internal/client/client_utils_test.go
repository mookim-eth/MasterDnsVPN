package client

import "testing"

func TestFragmentPayloadHandlesNonPositiveMTU(t *testing.T) {
	payload := []byte("abc")
	fragments := fragmentPayload(payload, 0)
	if len(fragments) != 1 {
		t.Fatalf("expected one fragment, got %d", len(fragments))
	}
	if string(fragments[0]) != "abc" {
		t.Fatalf("unexpected fragment payload: %q", string(fragments[0]))
	}

	fragments = fragmentPayload(nil, -1)
	if len(fragments) != 1 || len(fragments[0]) != 0 {
		t.Fatalf("expected a single empty fragment for empty payload, got %#v", fragments)
	}
}

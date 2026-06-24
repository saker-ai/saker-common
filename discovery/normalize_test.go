package discovery

import "testing"

func TestNormalizeBuildsBaseURLAndInstanceID(t *testing.T) {
	got, err := Normalize(ServiceInstance{ID: "stockhub", Scheme: "http", Address: "127.0.0.1", Port: 17090})
	if err != nil {
		t.Fatal(err)
	}
	if got.BaseURL != "http://127.0.0.1:17090" {
		t.Fatalf("BaseURL = %q", got.BaseURL)
	}
	if got.InstanceID == "" || got.Status != StatusPassing || got.Weight != 100 {
		t.Fatalf("normalized = %+v", got)
	}
}

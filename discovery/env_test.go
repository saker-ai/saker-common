package discovery

import (
	"context"
	"testing"
)

func TestStartFromEnvDisabled(t *testing.T) {
	t.Setenv("SAKER_DISCOVERY_ENABLED", "false")
	reg, err := StartFromEnv(context.Background(), ServiceInstance{ID: "webhub"}, EnvOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

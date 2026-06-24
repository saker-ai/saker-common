package discovery

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"
)

type EnvOptions struct {
	DefaultProviders string
}

type MultiRegistration struct {
	regs []*Registration
}

func StartFromEnv(ctx context.Context, instance ServiceInstance, opts EnvOptions) (*MultiRegistration, error) {
	if !envBool("SAKER_DISCOVERY_ENABLED") {
		return &MultiRegistration{}, nil
	}
	providers := envString("SAKER_DISCOVERY_PROVIDERS", opts.DefaultProviders)
	if providers == "" {
		providers = "mdns"
	}
	var regs []*Registration
	for _, providerName := range strings.Split(providers, ",") {
		providerName = strings.TrimSpace(providerName)
		if providerName == "" || providerName == "static" || providerName == "env" {
			continue
		}
		provider := providerFromEnv(providerName)
		if provider == nil {
			continue
		}
		reg, err := Start(ctx, provider, instance)
		if err != nil {
			_ = provider.Close()
			continue
		}
		regs = append(regs, reg)
	}
	return &MultiRegistration{regs: regs}, nil
}

func (m *MultiRegistration) Stop(ctx context.Context) error {
	var first error
	for _, reg := range m.regs {
		if err := reg.Stop(ctx); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func providerFromEnv(name string) Registrar {
	switch name {
	case "mdns":
		return NewMDNSRegistrar(MDNSConfig{
			ServiceType: envString("SAKER_DISCOVERY_MDNS_SERVICE_TYPE", "_saker._tcp"),
			Domain:      envString("SAKER_DISCOVERY_MDNS_DOMAIN", "local."),
		})
	case "redis":
		return NewRedisRegistrar(RedisConfig{
			Addr:     envString("SAKER_REDIS_ADDR", envString("WEBHUB_DISCOVERY_REDIS_ADDR", "127.0.0.1:6379")),
			Password: os.Getenv("SAKER_REDIS_PASSWORD"),
			Prefix:   envString("SAKER_REDIS_PREFIX", "saker:services"),
			TTL:      envDuration("SAKER_REDIS_TTL", 30*time.Second),
		})
	case "consul":
		return NewConsulRegistrar(ConsulConfig{
			Addr:  envString("SAKER_CONSUL_ADDR", envString("WEBHUB_DISCOVERY_CONSUL_ADDR", "127.0.0.1:8500")),
			Token: os.Getenv("SAKER_CONSUL_TOKEN"),
		})
	default:
		return nil
	}
}

func envString(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envBool(key string) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return false
	}
	parsed, err := strconv.ParseBool(value)
	return err == nil && parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

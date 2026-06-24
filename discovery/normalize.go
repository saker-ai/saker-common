package discovery

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func Normalize(svc ServiceInstance) (ServiceInstance, error) {
	svc.ID = strings.TrimSpace(svc.ID)
	svc.Name = strings.TrimSpace(svc.Name)
	svc.InstanceID = strings.TrimSpace(svc.InstanceID)
	svc.Scheme = strings.TrimSpace(svc.Scheme)
	if svc.Scheme == "" {
		svc.Scheme = "http"
	}
	svc.Address = strings.TrimSpace(svc.Address)
	svc.BaseURL = strings.TrimRight(strings.TrimSpace(svc.BaseURL), "/")
	if svc.HealthPath == "" {
		svc.HealthPath = "/healthz"
	}
	if !strings.HasPrefix(svc.HealthPath, "/") {
		svc.HealthPath = "/" + svc.HealthPath
	}
	if svc.Status == "" {
		svc.Status = StatusPassing
	}
	if svc.Weight <= 0 {
		svc.Weight = 100
	}
	if svc.TTL <= 0 {
		svc.TTL = 30 * time.Second
	}
	if svc.LastSeenAt.IsZero() {
		svc.LastSeenAt = time.Now().UTC()
	}
	if svc.StartedAt.IsZero() {
		svc.StartedAt = svc.LastSeenAt
	}
	if svc.BaseURL != "" {
		u, err := url.Parse(svc.BaseURL)
		if err == nil && u.Host != "" {
			svc.Scheme = u.Scheme
			svc.Address = u.Hostname()
			if port := u.Port(); port != "" {
				svc.Port, _ = strconv.Atoi(port)
			}
		}
	}
	if svc.BaseURL == "" && svc.Address != "" && svc.Port > 0 {
		svc.BaseURL = svc.Scheme + "://" + net.JoinHostPort(svc.Address, strconv.Itoa(svc.Port))
	}
	if svc.InstanceID == "" && svc.ID != "" && svc.Address != "" && svc.Port > 0 {
		svc.InstanceID = svc.ID + "-" + svc.Address + "-" + strconv.Itoa(svc.Port)
	}
	return svc, nil
}

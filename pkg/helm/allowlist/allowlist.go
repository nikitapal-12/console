package allowlist

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/klog/v2"
)

const (
	// ConfigMapNamespace is the namespace of the admin allowlist ConfigMap.
	ConfigMapNamespace = "openshift-console"
	// ConfigMapName is the ConfigMap cluster admins create to approve internal
	// Helm registries for namespace-scoped ProjectHelmChartRepository resources.
	// Data keys are "cidrs" and "hosts" (comma- or newline-separated).
	ConfigMapName = "helm-project-repo-allowlist"

	configMapRefresh = 30 * time.Second
	configMapTimeout = 5 * time.Second
)

// internalChartHostSuffixes and internalChartHostExact block cluster-internal
// hostnames that are reachable from the console pod. A CIDR allowlist does not
// waive these; an explicit host entry does.
var (
	internalChartHostSuffixes = []string{
		".svc",
		".svc.cluster.local",
		".pod.cluster.local",
	}
	internalChartHostExact = []string{
		"kubernetes",
		"kubernetes.default",
		"localhost",
	}
)

// List is a set of CIDRs and hostnames an administrator has approved for
// namespace-scoped Helm repository fetches. Link-local, loopback, and
// unspecified addresses are never approved, including when an entry would
// otherwise cover them.
type List struct {
	nets  []*net.IPNet
	hosts map[string]struct{}
}

var (
	mu            sync.Mutex
	static        List
	dynamic       List
	dynamicAt     time.Time
	core          corev1client.CoreV1Interface
	logReadFailed sync.Once
)

// SetStatic records the allowlist supplied by console configuration or flags.
func SetStatic(list List) {
	mu.Lock()
	static = list
	mu.Unlock()
}

// SetCoreClient enables refresh of the allowlist ConfigMap. A nil client
// disables ConfigMap refresh.
func SetCoreClient(client corev1client.CoreV1Interface) {
	mu.Lock()
	core = client
	dynamicAt = time.Time{}
	mu.Unlock()
}

// TestingReset clears static, dynamic, and client state.
func TestingReset() {
	mu.Lock()
	static = List{}
	dynamic = List{}
	dynamicAt = time.Time{}
	core = nil
	logReadFailed = sync.Once{}
	mu.Unlock()
}

// Current returns the merged static and ConfigMap allowlists.
func Current() List {
	maybeRefresh()
	mu.Lock()
	defer mu.Unlock()
	return static.merge(dynamic)
}

// Split separates a comma- or whitespace-separated list.
func Split(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ',', '\n', '\r', '\t', ' ':
			return true
		default:
			return false
		}
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// Parse builds an allowlist. Invalid CIDRs produce an error; valid entries
// are still returned so callers can keep the usable subset.
func Parse(cidrs, hosts []string) (List, error) {
	list := List{hosts: map[string]struct{}{}}
	var problems []string
	for _, cidr := range cidrs {
		n, err := parseNet(cidr)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		list.nets = append(list.nets, n)
	}
	for _, host := range hosts {
		host = normalizeHost(host)
		if host == "" {
			continue
		}
		list.hosts[host] = struct{}{}
	}
	if len(problems) > 0 {
		return list, fmt.Errorf("invalid helm project repository allowlist: %s", strings.Join(problems, "; "))
	}
	return list, nil
}

// AllowsHost reports whether host was explicitly approved.
func (l List) AllowsHost(host string) bool {
	if len(l.hosts) == 0 {
		return false
	}
	_, ok := l.hosts[normalizeHost(host)]
	return ok
}

// AllowsIP reports whether ip falls in an approved CIDR. Link-local, loopback,
// and unspecified addresses are never approved.
func (l List) AllowsIP(ip net.IP) bool {
	if ip == nil || nonOverridable(ip) || len(l.nets) == 0 {
		return false
	}
	for _, n := range l.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Permits reports whether host is explicitly approved or ip falls in an
// approved CIDR. Non-overridable addresses are never permitted.
func (l List) Permits(host string, ip net.IP) bool {
	if ip != nil && nonOverridable(ip) {
		return false
	}
	if l.AllowsHost(host) {
		return true
	}
	return l.AllowsIP(ip)
}

// IsClusterInternalHost reports whether hostname is an in-cluster service name.
func IsClusterInternalHost(hostname string) bool {
	h := normalizeHost(hostname)
	for _, exact := range internalChartHostExact {
		if h == exact {
			return true
		}
	}
	for _, suffix := range internalChartHostSuffixes {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}

func (l List) merge(other List) List {
	out := List{hosts: map[string]struct{}{}}
	out.nets = append(out.nets, l.nets...)
	out.nets = append(out.nets, other.nets...)
	for host := range l.hosts {
		out.hosts[host] = struct{}{}
	}
	for host := range other.hosts {
		out.hosts[host] = struct{}{}
	}
	return out
}

func maybeRefresh() {
	mu.Lock()
	client := core
	if client == nil || time.Since(dynamicAt) < configMapRefresh {
		mu.Unlock()
		return
	}
	dynamicAt = time.Now()
	mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), configMapTimeout)
	defer cancel()
	cm, err := client.ConfigMaps(ConfigMapNamespace).Get(ctx, ConfigMapName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			mu.Lock()
			dynamic = List{}
			mu.Unlock()
			return
		}
		logReadFailed.Do(func() {
			klog.Errorf("cannot read ConfigMap %s/%s (%v); namespace-scoped Helm repositories will keep blocking unapproved private addresses", ConfigMapNamespace, ConfigMapName, err)
		})
		return
	}

	parsed, parseErr := parseConfigMap(cm)
	if parseErr != nil {
		klog.Errorf("ConfigMap %s/%s: %v", ConfigMapNamespace, ConfigMapName, parseErr)
	}
	mu.Lock()
	dynamic = parsed
	mu.Unlock()
}

func parseConfigMap(cm *corev1.ConfigMap) (List, error) {
	if cm == nil || cm.Data == nil {
		return List{}, nil
	}
	return Parse(Split(cm.Data["cidrs"]), Split(cm.Data["hosts"]))
}

func parseNet(s string) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid CIDR or IP %q", s)
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func nonOverridable(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

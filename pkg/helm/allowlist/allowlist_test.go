package allowlist

import (
	"net"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestParseAndPermits(t *testing.T) {
	list, err := Parse(
		[]string{"10.0.0.0/8", "192.168.1.10", "not-a-cidr"},
		[]string{"Charts.Internal.Example.com.", "harbor.apps.example.com"},
	)
	if err == nil {
		t.Fatal("expected an error for the invalid CIDR")
	}
	if !list.AllowsIP(net.ParseIP("10.1.2.3")) {
		t.Fatal("expected 10.1.2.3 to be allowed by 10.0.0.0/8")
	}
	if !list.AllowsIP(net.ParseIP("192.168.1.10")) {
		t.Fatal("expected a bare IP entry to be treated as a single host")
	}
	if list.AllowsIP(net.ParseIP("192.168.1.11")) {
		t.Fatal("expected a neighboring address to stay blocked")
	}
	if list.AllowsIP(net.ParseIP("169.254.169.254")) {
		t.Fatal("expected link-local metadata to stay blocked")
	}
	if list.AllowsIP(net.ParseIP("127.0.0.1")) {
		t.Fatal("expected loopback to stay blocked")
	}
	if !list.AllowsHost("charts.internal.example.com") {
		t.Fatal("expected host match to be case-insensitive and ignore a trailing dot")
	}
	if !list.Permits("charts.internal.example.com", net.ParseIP("10.1.2.3")) {
		t.Fatal("expected an approved host to be permitted")
	}
	if list.Permits("metadata.example.com", net.ParseIP("169.254.169.254")) {
		t.Fatal("expected an approved host to still be rejected when it resolves to link-local")
	}
}

func TestNonOverridableEvenWhenCIDRCoversAll(t *testing.T) {
	list, err := Parse([]string{"0.0.0.0/0", "::/0"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !list.AllowsIP(net.ParseIP("10.0.0.5")) {
		t.Fatal("expected RFC1918 to be covered by 0.0.0.0/0")
	}
	for _, addr := range []string{"169.254.169.254", "127.0.0.1", "0.0.0.0", "::1", "fe80::1"} {
		if list.AllowsIP(net.ParseIP(addr)) {
			t.Fatalf("expected %s to stay blocked", addr)
		}
	}
}

func TestIsClusterInternalHost(t *testing.T) {
	internal := []string{
		"kubernetes",
		"kubernetes.default",
		"localhost",
		"chartmuseum.artifactory.svc",
		"chartmuseum.artifactory.svc.cluster.local",
		"pod.namespace.pod.cluster.local",
	}
	for _, host := range internal {
		if !IsClusterInternalHost(host) {
			t.Fatalf("expected %s to be cluster-internal", host)
		}
	}
	if IsClusterInternalHost("charts.example.com") || IsClusterInternalHost("10.0.0.5") {
		t.Fatal("expected public names and IP literals not to be cluster-internal")
	}
}

func TestCurrentMergesConfigMap(t *testing.T) {
	TestingReset()
	t.Cleanup(TestingReset)

	static, err := Parse([]string{"192.168.5.0/24"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	SetStatic(static)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ConfigMapName,
			Namespace: ConfigMapNamespace,
		},
		Data: map[string]string{
			"cidrs": "10.8.0.0/16",
			"hosts": "harbor.internal.example.com",
		},
	}
	SetCoreClient(fake.NewSimpleClientset(cm).CoreV1())

	got := Current()
	if !got.AllowsIP(net.ParseIP("192.168.5.9")) {
		t.Fatal("expected the static CIDR to remain in effect")
	}
	if !got.AllowsIP(net.ParseIP("10.8.0.4")) {
		t.Fatal("expected the ConfigMap CIDR to be loaded")
	}
	if !got.AllowsHost("harbor.internal.example.com") {
		t.Fatal("expected the ConfigMap host to be loaded")
	}
	if got.AllowsIP(net.ParseIP("10.9.0.1")) {
		t.Fatal("expected an address outside the allowlist to stay blocked")
	}
}

func TestSplit(t *testing.T) {
	got := Split(" 10.0.0.0/8, 172.16.0.0/12\n192.168.0.0/16 ")
	if len(got) != 3 || got[0] != "10.0.0.0/8" || got[2] != "192.168.0.0/16" {
		t.Fatalf("unexpected split result: %#v", got)
	}
	if Split("  ") != nil {
		t.Fatal("expected blank input to produce no entries")
	}
}

package buildkit

import (
	"os"
	"testing"

	"github.com/moby/buildkit/client/llb"
)

func TestGetProxy(t *testing.T) {
	var got llb.ProxyEnv
	var want llb.ProxyEnv

	// Test with configured proxy
	os.Setenv("HTTP_PROXY", "httpproxy")
	os.Setenv("HTTPS_PROXY", "httpsproxy")
	os.Setenv("NO_PROXY", "noproxy")
	got = GetProxy()
	want = llb.ProxyEnv{
		HTTPProxy:  "httpproxy",
		HTTPSProxy: "httpsproxy",
		NoProxy:    "noproxy",
		AllProxy:   "httpproxy",
	}
	if got != want {
		t.Errorf("unexpected proxy config, got %#v want %#v", got, want)
	}

	// Test with unconfigured proxy
	os.Unsetenv("HTTP_PROXY")
	os.Unsetenv("HTTPS_PROXY")
	os.Unsetenv("NO_PROXY")
	got = GetProxy()
	want = llb.ProxyEnv{
		HTTPProxy:  "",
		HTTPSProxy: "",
		NoProxy:    "",
		AllProxy:   "",
	}
	if got != want {
		t.Errorf("unexpected proxy config, got %#v want %#v", got, want)
	}
}

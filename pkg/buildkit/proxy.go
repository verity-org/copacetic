package buildkit

import (
	"os"

	"github.com/moby/buildkit/client/llb"
)

func getEnvAny(names ...string) string {
	for _, n := range names {
		if val := os.Getenv(n); val != "" {
			return val
		}
	}
	return ""
}

func GetProxy() llb.ProxyEnv {
	return llb.ProxyEnv{
		HTTPProxy:  getEnvAny("HTTP_PROXY"),
		HTTPSProxy: getEnvAny("HTTPS_PROXY"),
		NoProxy:    getEnvAny("NO_PROXY"),
		AllProxy:   getEnvAny("HTTP_PROXY"),
	}
}

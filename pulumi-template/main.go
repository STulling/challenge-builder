package main

import (
	_ "embed"
	"strconv"
	"strings"

	"github.com/ctfer-io/chall-manager/sdk"
	k8s "github.com/ctfer-io/chall-manager/sdk/kubernetes"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"gopkg.in/yaml.v3"
)

// Example Pulumi program for deploying a challenge using Kompose

//go:embed docker-compose.yaml
var dc string

//go:embed challenge.yaml
var config string

var CtfDomain string
var Subdomain string

type ChallengeConfig struct {
	Name          string
	Description   string
	Category      string
	Type          string
	IsHTTP        bool
	DestroyOnFlag bool
	Scenario      string
	Shared        bool
	Timeout       int
	ManaCost      int
	Max           int
	Min           int
	Subdomain     string
	EnvFlag       bool
	ServeFolder   string
	Tags          []string
	Topics        []string
	Attribution   string
	Initial       int
	Decay         int
	Minimum       int
	Function      string
}

type DockerCompose struct {
	Version  string
	Services map[string]Service
}
type Service struct {
	Image       string
	Ports       []string
	Environment map[string]string
	DependsOn   []string `yaml:"depends_on"`
}

func parsePort(p string) int {
	// strip protocol suffix if present: "1234/tcp"
	if idx := strings.Index(p, "/"); idx != -1 {
		p = p[:idx]
	}
	// split on ':' and take the right-most segment as the container port
	parts := strings.Split(p, ":")
	last := parts[len(parts)-1]
	if last == "" {
		return 0
	}
	i, err := strconv.Atoi(last)
	if err != nil {
		return 0
	}
	return i
}

func main() {
	var cfg ChallengeConfig
	// Parse the embedded YAML configuration into the cfg struct
	if err := yaml.Unmarshal([]byte(config), &cfg); err != nil {
		panic(err)
	}
	var dcfg DockerCompose
	if err := yaml.Unmarshal([]byte(dc), &dcfg); err != nil {
		panic(err)
	}
	var firstService string
	for name, svc := range dcfg.Services {
		if len(svc.Ports) > 0 {
			firstService = name
			break
		}
	}
	if firstService == "" {
		panic("no service with exposed ports found")
	}
	// Get ExposeType based on cfg.IsHTTP
	var exposeType k8s.ExposeType
	if cfg.IsHTTP {
		exposeType = k8s.ExposeIngress
	} else {
		exposeType = k8s.ExposeIngressTCP
	}
	sdk.Run(func(req *sdk.Request, resp *sdk.Response, opts ...pulumi.ResourceOption) error {
		kmp, err := k8s.NewKompose(req.Ctx, cfg.Name, &k8s.KomposeArgs{
			Identity: pulumi.String(req.Config.Identity),
			Hostname: pulumi.String(cfg.Name + "." + Subdomain + "." + CtfDomain),
			YAML:     pulumi.String(dc),
			Ports: k8s.PortBindingMapArray{
				firstService: {
					k8s.PortBindingArgs{
						Port:       pulumi.Int(parsePort(dcfg.Services[firstService].Ports[0])),
						ExposeType: exposeType,
					},
				},
			},
			IngressNamespace: pulumi.String("traefik"),
		}, opts...)
		if err != nil {
			return err
		}
		// if the challenge is HTTP, set the ConnectionInfo to the URL of the first service
		if cfg.IsHTTP {
			resp.ConnectionInfo = pulumi.Sprintf("https://%s", kmp.URLs.MapIndex(pulumi.String(firstService)).MapIndex(pulumi.String(dcfg.Services[firstService].Ports[0])))
		} else {
			resp.ConnectionInfo = pulumi.Sprintf("ncat --ssl %s 1337", kmp.URLs.MapIndex(pulumi.String(firstService)).MapIndex(pulumi.String(dcfg.Services[firstService].Ports[0])))
		}
		return nil
	})
}

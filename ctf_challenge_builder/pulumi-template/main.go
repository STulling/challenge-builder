package main

import (
	"crypto/sha1"
	_ "embed"
	"encoding/hex"
	"fmt"
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
	Name string
	Ctfd CTFDConfig
}

type CTFDConfig struct {
	Slug string
}

type DockerCompose struct {
	Version  string
	Services map[string]Service
}
type Service struct {
	Image       string
	Ports       []string
	Environment map[string]string `yaml:"environment"`
	DependsOn   []string          `yaml:"depends_on"`
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

// randName generates a deterministic name from a seed (same as kompose.go)
func randName(seed string) string {
	h := sha1.New()
	h.Write([]byte(seed))
	return hex.EncodeToString(h.Sum(nil))
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

	sdk.Run(func(req *sdk.Request, resp *sdk.Response, opts ...pulumi.ResourceOption) error {
		// Collect env overrides from config
		envOverrides := map[string]string{}
		for key, value := range req.Config.Additional {
			if strings.HasPrefix(key, "env.") {
				envOverrides[strings.TrimPrefix(key, "env.")] = value
			}
		}

		// Build port bindings for all services with exposed ports
		portBindings := k8s.PortBindingMapArray{}
		// Track which ports should be added to ConnectionInfo (uppercase protocol = add to ConnectionInfo)
		type portInfo struct {
			serviceName       string
			port              int
			protocol          string // "HTTP" or "TCP" (uppercase means add to ConnectionInfo)
			isHTTP            bool
			addToConnInfo     bool
			tcpIndexInService int    // Index of this TCP port within its service (for entrypoint selection)
			publicURL         string // Pre-computed public URL for this port
		}
		var exposedPorts []portInfo

		identity := req.Config.Identity
		hostname := Subdomain + "." + CtfDomain

		for serviceName, svc := range dcfg.Services {
			if len(svc.Ports) == 0 {
				continue
			}
			var bindings []k8s.PortBindingArgs
			portIndexInService := 0 // Track port index within this service (matches j in kompose.go)
			for _, p := range svc.Ports {
				port := parsePort(p)
				if port == 0 {
					continue
				}
				// Check for protocol suffix: "1234/HTTP", "1234/http", "1234/TCP", "1234/tcp"
				var exposeType k8s.ExposeType
				var protocol string
				var isHTTP bool
				var addToConnInfo bool

				if idx := strings.Index(p, "/"); idx != -1 {
					protocol = p[idx+1:]
				} else {
					protocol = "tcp" // default to tcp, lowercase = don't add to ConnectionInfo
				}

				// Check if HTTP or TCP based on protocol string
				if strings.ToLower(protocol) == "http" {
					exposeType = k8s.ExposeIngress
					isHTTP = true
				} else {
					exposeType = k8s.ExposeIngressTCP
					isHTTP = false
				}

				// Uppercase protocol means add to ConnectionInfo
				addToConnInfo = protocol == strings.ToUpper(protocol)

				// Pre-compute the public URL using the same logic as kompose.go
				seed := fmt.Sprintf("%s-%s-%d/%s", identity, serviceName, port, strings.ToUpper(protocol))
				uniqueName := randName(seed)[:len(identity)]
				uniqueHost := fmt.Sprintf("%s.%s", uniqueName, hostname)

				var publicURL string
				if isHTTP {
					publicURL = fmt.Sprintf("https://%s", uniqueHost)
				} else {
					traefikPort := 1337 + (portIndexInService % 6)
					publicURL = fmt.Sprintf("%s:%d", uniqueHost, traefikPort)
				}

				bindings = append(bindings, k8s.PortBindingArgs{
					Port:       pulumi.Int(port),
					ExposeType: exposeType,
				})

				exposedPorts = append(exposedPorts, portInfo{
					serviceName:       serviceName,
					port:              port,
					protocol:          strings.ToUpper(protocol),
					isHTTP:            isHTTP,
					addToConnInfo:     addToConnInfo,
					tcpIndexInService: portIndexInService,
					publicURL:         publicURL,
				})
				portIndexInService++
			}
			if len(bindings) > 0 {
				portBindings[serviceName] = bindings
			}
		}

		if len(portBindings) == 0 {
			return fmt.Errorf("no services with exposed ports found")
		}

		// Inject public URLs as environment variables into all services
		// Format: PUBLIC_URL_<SERVICE>_<PORT> (e.g., PUBLIC_URL_ANVIL_8545)
		for _, pi := range exposedPorts {
			envKey := fmt.Sprintf("PUBLIC_URL_%s_%d", strings.ToUpper(pi.serviceName), pi.port)
			for name, svc := range dcfg.Services {
				if svc.Environment == nil {
					svc.Environment = map[string]string{}
				}
				svc.Environment[envKey] = pi.publicURL
				dcfg.Services[name] = svc
			}
		}

		// Apply additional env overrides from config
		if len(envOverrides) > 0 {
			for name, svc := range dcfg.Services {
				if svc.Environment == nil {
					svc.Environment = map[string]string{}
				}
				for envKey, envValue := range envOverrides {
					svc.Environment[envKey] = envValue
				}
				dcfg.Services[name] = svc
			}
		}

		// Re-marshal the docker-compose with injected env vars
		updated, err := yaml.Marshal(dcfg)
		if err != nil {
			return err
		}
		dc = string(updated)

		kmp, err := k8s.NewKompose(req.Ctx, cfg.Name, &k8s.KomposeArgs{
			Identity:         pulumi.String(req.Config.Identity),
			Hostname:         pulumi.String(Subdomain + "." + CtfDomain),
			YAML:             pulumi.String(dc),
			Ports:            portBindings,
			IngressNamespace: pulumi.String("traefik"),
		}, opts...)
		if err != nil {
			return err
		}

		// Build ConnectionInfo from all ports that should be included
		var connectionInfoParts []pulumi.StringInput
		for _, pi := range exposedPorts {
			if !pi.addToConnInfo {
				continue
			}
			portName := fmt.Sprintf("%d/%s", pi.port, pi.protocol)
			url := kmp.URLs.MapIndex(pulumi.String(pi.serviceName)).MapIndex(pulumi.String(portName))
			if pi.isHTTP {
				connectionInfoParts = append(connectionInfoParts, pulumi.Sprintf("https://%s", url))
			} else {
				// TCP port uses entrypoint ctf0-ctf5 (ports 1337-1342) based on port index within service
				traefikPort := 1337 + (pi.tcpIndexInService % 6)
				connectionInfoParts = append(connectionInfoParts, pulumi.Sprintf("ncat --ssl %s %d", url, traefikPort))
			}
		}

		if len(connectionInfoParts) == 1 {
			resp.ConnectionInfo = connectionInfoParts[0]
		} else if len(connectionInfoParts) > 1 {
			// Join with '&' separator
			resp.ConnectionInfo = connectionInfoParts[0]
			for i := 1; i < len(connectionInfoParts); i++ {
				resp.ConnectionInfo = pulumi.Sprintf("%s&%s", resp.ConnectionInfo, connectionInfoParts[i])
			}
		}

		return nil
	})
}

package main

import (
	"crypto/sha1"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ctfer-io/chall-manager/sdk"
	k8s "github.com/ctfer-io/chall-manager/sdk/kubernetes"
	yamlv2 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/yaml/v2"
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
	Name       string
	Ctfd       CTFDConfig
	DynamicIAC DynamicIACConfig `yaml:"dynamic_iac"`
}

type CTFDConfig struct {
	Slug string
}

type DynamicIACConfig struct {
	Entrypoints []EntrypointConfig `yaml:"entrypoints"`
}

type EntrypointConfig struct {
	Name    string `yaml:"name" json:"name"`
	Prefix  string `yaml:"prefix" json:"prefix"`
	Service string `yaml:"service" json:"service"`
	Port    int    `yaml:"port" json:"port"`
}

type DockerCompose struct {
	Version  string
	Services map[string]Service
}

type ComposeEnvironment map[string]string

func (e *ComposeEnvironment) UnmarshalYAML(value *yaml.Node) error {
	if value == nil {
		*e = ComposeEnvironment{}
		return nil
	}

	switch value.Kind {
	case yaml.MappingNode:
		var envMap map[string]string
		if err := value.Decode(&envMap); err != nil {
			return err
		}
		*e = ComposeEnvironment(envMap)
		return nil

	case yaml.SequenceNode:
		envMap := make(map[string]string, len(value.Content))
		for _, item := range value.Content {
			entry := item.Value
			key, rawValue, found := strings.Cut(entry, "=")
			if found {
				envMap[key] = rawValue
			} else {
				envMap[key] = ""
			}
		}
		*e = ComposeEnvironment(envMap)
		return nil

	case 0:
		*e = ComposeEnvironment{}
		return nil
	}

	return fmt.Errorf("unsupported environment format in docker-compose")
}

type Service struct {
	Image       string
	Ports       []string
	Expose      []string           `yaml:"expose"`
	Environment ComposeEnvironment `yaml:"environment"`
	DependsOn   []string           `yaml:"depends_on"`
}

type portInfo struct {
	serviceName       string
	port              int
	protocol          string // Display protocol: "HTTP" or "TCP"
	bindingProtocol   string // Underlying transport protocol used in Kompose URL keys
	isHTTP            bool
	addToConnInfo     bool
	tcpIndexInService int    // Index of this TCP port within its service (for entrypoint selection)
	publicURL         string // Pre-computed public URL for this port
}

func sanitizeComposeForKompose(in DockerCompose) DockerCompose {
	out := DockerCompose{
		Version:  in.Version,
		Services: make(map[string]Service, len(in.Services)),
	}

	for name, svc := range in.Services {
		sanitizedPorts := make([]string, 0, len(svc.Ports))
		for _, port := range svc.Ports {
			switch {
			case strings.HasSuffix(port, "/HTTP"):
				sanitizedPorts = append(sanitizedPorts, strings.TrimSuffix(port, "/HTTP")+"/tcp")
			case strings.HasSuffix(port, "/http"):
				sanitizedPorts = append(sanitizedPorts, strings.TrimSuffix(port, "/http")+"/tcp")
			default:
				sanitizedPorts = append(sanitizedPorts, port)
			}
		}

		copiedEnv := map[string]string{}
		for k, v := range svc.Environment {
			copiedEnv[k] = v
		}

		copiedDependsOn := append([]string(nil), svc.DependsOn...)
		copiedExpose := append([]string(nil), svc.Expose...)

		out.Services[name] = Service{
			Image:       svc.Image,
			Ports:       sanitizedPorts,
			Expose:      copiedExpose,
			Environment: copiedEnv,
			DependsOn:   copiedDependsOn,
		}
	}

	return out
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

func parseProtocol(p string) string {
	if idx := strings.Index(p, "/"); idx != -1 {
		return p[idx+1:]
	}
	return "tcp"
}

// randName generates a deterministic name from a seed (same as kompose.go).
func randName(seed string) string {
	h := sha1.New()
	h.Write([]byte(seed))
	return hex.EncodeToString(h.Sum(nil))
}

var invalidHostPrefixChars = regexp.MustCompile(`[^a-z0-9-]+`)

func sanitizeHostPrefix(prefix string) string {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	prefix = invalidHostPrefixChars.ReplaceAllString(prefix, "-")
	prefix = strings.Trim(prefix, "-")
	if prefix == "" {
		return "endpoint"
	}
	return prefix
}

func endpointHost(prefix string, identity string, hostname string) string {
	return fmt.Sprintf("%s-%s.%s", sanitizeHostPrefix(prefix), identity, hostname)
}

func tcpEntrypointPort(index int) int {
	return 1337 + (index % 6)
}

func routeName(identity string, service string, port int, prefix string) string {
	return fmt.Sprintf("cm-%s-%s-%d-%s", identity, sanitizeHostPrefix(service), port, sanitizeHostPrefix(prefix))
}

func endpointValue(isHTTP bool, host string, tcpPort int) string {
	if isHTTP {
		return fmt.Sprintf("https://%s", host)
	}
	return fmt.Sprintf("ncat --ssl %s %d", host, tcpPort)
}

type connectionEndpoint struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value"`
}

type selectedEndpoint struct {
	portInfo portInfo
	name     string
	prefix   string
}

func connectionInfo(endpoints []connectionEndpoint) (string, error) {
	if len(endpoints) == 0 {
		return "", nil
	}
	if len(endpoints) == 1 {
		return endpoints[0].Value, nil
	}
	data, err := json.Marshal(endpoints)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func httpRouteYAML(identity string, service string, port int, host string, prefix string) string {
	return fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: %s
  namespace: %s
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: web,websecure
    traefik.ingress.kubernetes.io/router.middlewares: %s-%s-redirect-https@kubernetescrd
    traefik.ingress.kubernetes.io/router.tls: "true"
spec:
  ingressClassName: traefik
  rules:
    - host: %s
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: %s
                port:
                  number: %d
`, routeName(identity, service, port, prefix), identity, identity, identity, host, service, port)
}

func tcpRouteYAML(identity string, service string, port int, host string, prefix string, tcpIndex int) string {
	return fmt.Sprintf(`apiVersion: traefik.io/v1alpha1
kind: IngressRouteTCP
metadata:
  name: %s
  namespace: %s
spec:
  entryPoints:
  - ctf%d
  routes:
  - match: HostSNI(`+"`%s`"+`)
    services:
    - name: %s
      port: %d
  tls: {}
`, routeName(identity, service, port, prefix), identity, tcpIndex%6, host, service, port)
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
		var exposedPorts []portInfo

		identity := req.Config.Identity
		hostname := Subdomain + "." + CtfDomain

		for serviceName, svc := range dcfg.Services {
			if len(svc.Ports) == 0 && len(svc.Expose) == 0 {
				continue
			}
			bindings := k8s.PortBindingArray{}
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

				protocol = parseProtocol(p)

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

				seed := fmt.Sprintf("%s-%s-%d/%s", identity, serviceName, port, strings.ToUpper(protocol))
				uniqueName := randName(seed)[:len(identity)]
				publicHost := fmt.Sprintf("%s.%s", uniqueName, hostname)
				var publicURL string
				if isHTTP {
					publicURL = fmt.Sprintf("https://%s", publicHost)
				} else {
					publicURL = fmt.Sprintf("%s:%d", publicHost, tcpEntrypointPort(portIndexInService))
				}

				bindings = append(bindings, k8s.PortBindingArgs{
					Port:       pulumi.Int(port),
					ExposeType: exposeType,
				})

				exposedPorts = append(exposedPorts, portInfo{
					serviceName:       serviceName,
					port:              port,
					protocol:          strings.ToUpper(protocol),
					bindingProtocol:   "TCP",
					isHTTP:            isHTTP,
					addToConnInfo:     addToConnInfo,
					tcpIndexInService: portIndexInService,
					publicURL:         publicURL,
				})
				portIndexInService++
			}

			for _, p := range svc.Expose {
				port := parsePort(p)
				if port == 0 {
					continue
				}

				bindings = append(bindings, k8s.PortBindingArgs{
					Port: pulumi.Int(port),
				})
			}
			if len(bindings) > 0 {
				portBindings[serviceName] = bindings
			}
		}

		if len(portBindings) == 0 {
			return fmt.Errorf("no services with exposed ports found")
		}

		deploymentCompose := sanitizeComposeForKompose(dcfg)

		// Inject public URLs as environment variables into all services
		// Format: PUBLIC_URL_<SERVICE>_<PORT> (e.g., PUBLIC_URL_ANVIL_8545)
		for _, pi := range exposedPorts {
			envKey := fmt.Sprintf("PUBLIC_URL_%s_%d", strings.ToUpper(pi.serviceName), pi.port)
			for name, svc := range deploymentCompose.Services {
				if svc.Environment == nil {
					svc.Environment = map[string]string{}
				}
				svc.Environment[envKey] = pi.publicURL
				deploymentCompose.Services[name] = svc
			}
		}

		// Apply additional env overrides from config
		if len(envOverrides) > 0 {
			for name, svc := range deploymentCompose.Services {
				if svc.Environment == nil {
					svc.Environment = map[string]string{}
				}
				for envKey, envValue := range envOverrides {
					svc.Environment[envKey] = envValue
				}
				deploymentCompose.Services[name] = svc
			}
		}

		// Re-marshal the docker-compose with injected env vars
		updated, err := yaml.Marshal(deploymentCompose)
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

		selectedEndpoints := []selectedEndpoint{}
		if len(cfg.DynamicIAC.Entrypoints) > 0 {
			for _, entrypoint := range cfg.DynamicIAC.Entrypoints {
				found := false
				for _, pi := range exposedPorts {
					if pi.serviceName == entrypoint.Service && pi.port == entrypoint.Port {
						if entrypoint.Name == "" {
							entrypoint.Name = entrypoint.Service
						}
						if entrypoint.Prefix == "" {
							entrypoint.Prefix = entrypoint.Name
						}
						selectedEndpoints = append(selectedEndpoints, selectedEndpoint{
							portInfo: pi,
							name:     entrypoint.Name,
							prefix:   entrypoint.Prefix,
						})
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("dynamic_iac entrypoint %q references unknown compose port %s:%d", entrypoint.Name, entrypoint.Service, entrypoint.Port)
				}
			}
		} else {
			for _, pi := range exposedPorts {
				if pi.addToConnInfo {
					label := fmt.Sprintf("%s %d/%s", pi.serviceName, pi.port, pi.protocol)
					prefix := fmt.Sprintf("%s-%d", pi.serviceName, pi.port)
					selectedEndpoints = append(selectedEndpoints, selectedEndpoint{
						portInfo: pi,
						name:     label,
						prefix:   prefix,
					})
				}
			}
		}

		var endpoints []connectionEndpoint
		routeOpts := append([]pulumi.ResourceOption{}, opts...)
		routeOpts = append(routeOpts, pulumi.DependsOn([]pulumi.Resource{kmp}))
		for i, selected := range selectedEndpoints {
			pi := selected.portInfo
			endpointName := selected.name
			endpointPrefix := selected.prefix
			host := endpointHost(endpointPrefix, identity, hostname)
			value := endpointValue(pi.isHTTP, host, tcpEntrypointPort(pi.tcpIndexInService))

			var routeYAML string
			if pi.isHTTP {
				routeYAML = httpRouteYAML(identity, pi.serviceName, pi.port, host, endpointPrefix)
			} else {
				routeYAML = tcpRouteYAML(identity, pi.serviceName, pi.port, host, endpointPrefix, pi.tcpIndexInService)
			}

			_, err := yamlv2.NewConfigGroup(req.Ctx, fmt.Sprintf("readable-route-%d", i), &yamlv2.ConfigGroupArgs{
				Yaml: pulumi.String(routeYAML),
			}, routeOpts...)
			if err != nil {
				return err
			}

			endpoints = append(endpoints, connectionEndpoint{
				Name:  endpointName,
				Value: value,
			})
		}

		info, err := connectionInfo(endpoints)
		if err != nil {
			return err
		}
		if info != "" {
			resp.ConnectionInfo = pulumi.String(info).ToStringOutput()
		}

		return nil
	})
}

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog"

	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
	certmanagerv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/nesv/go-dynect/dynect"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	cmd.RunWebhookServer(GroupName,
		&dynDNSProviderSolver{},
	)
}

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type dynDNSProviderSolver struct {
	client *kubernetes.Clientset
}

// ZonePublishRequest is missing from dynect but the notes field is a nice place to let
// external-dns report some internal info during commit
type ZonePublishRequest struct {
	Publish bool   `json:"publish"`
	Notes   string `json:"notes"`
}

type ZonePublishResponse struct {
	dynect.ResponseBlock
	Data map[string]interface{} `json:"data"`
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
type dynDNSProviderConfig struct {
	Username          string                          `json:"username"`
	PasswordSecretRef certmanagerv1.SecretKeySelector `json:"passwordSecretRef"`
	CustomerName      string                          `json:"customerName"`
	ZoneName          string                          `json:"zonename"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
func (c *dynDNSProviderSolver) Name() string {
	return "dyndns"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
func (c *dynDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}
	klog.V(4).Infof("creating a new dyndns record for: %s, fqdn: %s, value: %s\n", ch.DNSName, ch.ResolvedFQDN, ch.Key)
	return c.createRecord(&cfg, ch)
}

func (c *dynDNSProviderSolver) validate(cfg *dynDNSProviderConfig) error {
	// Check that the username is defined
	if cfg.Username == "" {
		return errors.New("No dyndns username provided")
	}

	// Check that the customerName is defined
	if cfg.CustomerName == "" {
		return errors.New("No dyndns customerName provided")
	}

	// Check that the zoneName is defined
	if cfg.ZoneName == "" {
		return errors.New("No dyndns zoneName provided")
	}

	// Try to load the Password key
	if cfg.PasswordSecretRef.LocalObjectReference.Name == "" {
		return errors.New("No dydns password key provided")
	}

	return nil
}

func (c *dynDNSProviderSolver) dynClient(cfg *dynDNSProviderConfig, namespace string) (*dynect.Client, error) {
	if err := c.validate(cfg); err != nil {
		return nil, err
	}

	sec, err := c.client.CoreV1().Secrets(namespace).Get(cfg.PasswordSecretRef.LocalObjectReference.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	secBytes, ok := sec.Data[cfg.PasswordSecretRef.Key]
	if !ok {
		return nil, fmt.Errorf("Key %q not found in secret \"%s/%s\"", cfg.PasswordSecretRef.Key, cfg.PasswordSecretRef.LocalObjectReference.Name, namespace)
	}

	password := string(secBytes)

	dynClient := dynect.NewClient(cfg.CustomerName)

	var resp dynect.LoginResponse
	var req = dynect.LoginBlock{
		Username:     cfg.Username,
		Password:     password,
		CustomerName: cfg.CustomerName,
	}

	errSession := dynClient.Do("POST", "Session", req, &resp)
	if errSession != nil {
		klog.Errorf("Problem creating a session error: %s", errSession)
		return nil, err
	} else {
		klog.Infof("Successfully created Dyn session")
	}
	dynClient.Token = resp.Data.Token

	return dynClient, nil
}

func (c *dynDNSProviderSolver) createRecord(cfg *dynDNSProviderConfig, ch *v1alpha1.ChallengeRequest) error {
	link := fmt.Sprintf("%sRecord/%s/%s/", "TXT", ch.ResolvedZone, ch.ResolvedFQDN)
	klog.V(4).Infof("the link is: %s", link)

	recordData := dynect.DataBlock{}
	recordData.TxtData = ch.Key
	record := dynect.RecordRequest{
		TTL:   "60",
		RData: recordData,
	}

	response := dynect.RecordResponse{}
	dynClient, err := c.dynClient(cfg, ch.ResourceNamespace)
	if err != nil {
		klog.Errorf("Error creating dynClient: %v", err)
		return err
	}
	err = dynClient.Do("POST", link, record, &response)
	klog.Infof("Creating record %s: %+v,", link, errorOrValue(err, &response))
	if err != nil {
		klog.Errorf("Error creating record: %v, %v", record, err)
		return err
	}

	commit(c, cfg, ch)

	klog.V(4).Info("sleeping for 1.3 seconds")
	time.Sleep(1300 * time.Millisecond)

	return nil
}

func errorOrValue(err error, value interface{}) interface{} {
	if err == nil {
		return value
	}

	return err
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *dynDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("deleting a dyndns record for domain: %s\n", ch.ResolvedFQDN)

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	link := fmt.Sprintf("%sRecord/%s/%s/", "TXT", ch.ResolvedZone, ch.ResolvedFQDN)
	klog.Infof("deleting record: %s", link)
	response := dynect.RecordResponse{}
	dynClient, err := c.dynClient(&cfg, ch.ResourceNamespace)
	if err != nil {
		klog.Errorf("Error creating dynClient: %v", err)
		return err
	}
	err = dynClient.Do("DELETE", link, nil, &response)
	klog.Infof("Deleting record %s: %+v\n", link, errorOrValue(err, &response))
	if err != nil {
		klog.Errorf("Error deleting domain name: %s, %v", link, err)
		return err
	}

	commit(c, &cfg, ch)

	return nil
}

// Initialize will be called when the webhook first starts.
func (c *dynDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (dynDNSProviderConfig, error) {
	cfg := dynDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

// commit commits all pending changes. It will always attempt to commit, if there are no
func commit(c *dynDNSProviderSolver, cfg *dynDNSProviderConfig, ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("Committing changes")
	// extra call if in debug mode to fetch pending changes
	hostName, err := os.Hostname()
	if err != nil {
		hostName = "unknown-host"
	}
	notes := fmt.Sprintf("Change by external-dns@%s, DynAPI@%s, %s on %s",
		"external-dns-client",
		"external-dns-client-version",
		time.Now().Format(time.RFC3339),
		hostName,
	)

	zonePublish := ZonePublishRequest{
		Publish: true,
		Notes:   notes,
	}

	response := ZonePublishResponse{}

	klog.Infof("Committing changes for zone %s: %+v", cfg.ZoneName, errorOrValue(err, &response))

	link := fmt.Sprintf("Zone/%s/", cfg.ZoneName)
	dynClient, err := c.dynClient(cfg, ch.ResourceNamespace)
	if err != nil {
		klog.Errorf("Error creating dynClient: %v", err)
		return err
	}
	err = dynClient.Do("PUT", link, &zonePublish, &response)
	klog.Infof("Creating record %s: %+v,", link, errorOrValue(err, &response))
	if err != nil {
		klog.Errorf("Error creating record: %v, %v", zonePublish, err)
		return err
	}

	if err != nil {
		klog.Error("Error committing changes to zone, error: ", err)
		return err
	} else {
		klog.Info(response)
	}

	return nil
}

// Package trust provides mTLS implementation for ECPS-Go SDK
package trust

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// NodeIdentity represents identity information for an ECPS node
type NodeIdentity struct {
	NodeID             string   `json:"node_id"`
	CommonName         string   `json:"common_name"`
	Organization       string   `json:"organization"`
	OrganizationalUnit string   `json:"organizational_unit"`
	Country            string   `json:"country"`
	State              string   `json:"state"`
	Locality           string   `json:"locality"`
	Email              string   `json:"email,omitempty"`
	DNSNames           []string `json:"dns_names,omitempty"`
	IPAddresses        []string `json:"ip_addresses,omitempty"`
}

// MTLSConfig holds configuration for mTLS setup
type MTLSConfig struct {
	CACertPath     string `json:"ca_cert_path"`
	ServerCertPath string `json:"server_cert_path"`
	ServerKeyPath  string `json:"server_key_path"`
	ClientCertPath string `json:"client_cert_path"`
	ClientKeyPath  string `json:"client_key_path"`
	VerifyMode     tls.ClientAuthType
	CheckHostname  bool
}

// MTLSCertificateManager manages mTLS certificates for ECPS nodes
type MTLSCertificateManager struct {
	certDir        string
	caKeyPath      string
	caCertPath     string
	serverKeyPath  string
	serverCertPath string
	clientKeyPath  string
	clientCertPath string
}

// NewMTLSCertificateManager creates a new certificate manager
func NewMTLSCertificateManager(certDir string) *MTLSCertificateManager {
	if certDir == "" {
		homeDir, _ := os.UserHomeDir()
		certDir = filepath.Join(homeDir, ".ecps", "certs")
	}

	// Create certificate directory
	os.MkdirAll(certDir, 0700)

	return &MTLSCertificateManager{
		certDir:        certDir,
		caKeyPath:      filepath.Join(certDir, "ca-key.pem"),
		caCertPath:     filepath.Join(certDir, "ca-cert.pem"),
		serverKeyPath:  filepath.Join(certDir, "server-key.pem"),
		serverCertPath: filepath.Join(certDir, "server-cert.pem"),
		clientKeyPath:  filepath.Join(certDir, "client-key.pem"),
		clientCertPath: filepath.Join(certDir, "client-cert.pem"),
	}
}

// GenerateCACertificate generates a Certificate Authority certificate
func (m *MTLSCertificateManager) GenerateCACertificate(identity *NodeIdentity, validityDays int) (*rsa.PrivateKey, *x509.Certificate, error) {
	log.Printf("Generating CA certificate for %s", identity.CommonName)

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{identity.Country},
			Province:           []string{identity.State},
			Locality:           []string{identity.Locality},
			Organization:       []string{identity.Organization},
			OrganizationalUnit: []string{identity.OrganizationalUnit},
			CommonName:         identity.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(validityDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	if identity.Email != "" {
		template.EmailAddresses = []string{identity.Email}
	}

	// Add DNS names
	template.DNSNames = append(template.DNSNames, identity.CommonName)
	if identity.DNSNames != nil {
		template.DNSNames = append(template.DNSNames, identity.DNSNames...)
	}

	// Add IP addresses
	for _, ipStr := range identity.IPAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	log.Printf("Generated CA certificate with serial: %s", cert.SerialNumber.String())
	return privateKey, cert, nil
}

// GenerateNodeCertificate generates a node certificate signed by the CA
func (m *MTLSCertificateManager) GenerateNodeCertificate(
	identity *NodeIdentity,
	caPrivateKey *rsa.PrivateKey,
	caCertificate *x509.Certificate,
	isServer bool,
	validityDays int,
) (*rsa.PrivateKey, *x509.Certificate, error) {
	certType := "client"
	if isServer {
		certType = "server"
	}
	log.Printf("Generating %s certificate for %s", certType, identity.CommonName)

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Country:            []string{identity.Country},
			Province:           []string{identity.State},
			Locality:           []string{identity.Locality},
			Organization:       []string{identity.Organization},
			OrganizationalUnit: []string{identity.OrganizationalUnit},
			CommonName:         identity.CommonName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Duration(validityDays) * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{},
	}

	if identity.Email != "" {
		template.EmailAddresses = []string{identity.Email}
	}

	// Set key usage based on certificate type
	if isServer {
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	} else {
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}

	// Add DNS names
	template.DNSNames = append(template.DNSNames, identity.CommonName)
	if identity.DNSNames != nil {
		template.DNSNames = append(template.DNSNames, identity.DNSNames...)
	}

	// Add IP addresses
	for _, ipStr := range identity.IPAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCertificate, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	log.Printf("Generated %s certificate with serial: %s", certType, cert.SerialNumber.String())
	return privateKey, cert, nil
}

// SaveCertificate saves a private key and certificate to files
func (m *MTLSCertificateManager) SaveCertificate(privateKey *rsa.PrivateKey, certificate *x509.Certificate, keyPath, certPath string) error {
	// Save private key
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyFile.Close()

	keyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	if err := pem.Encode(keyFile, keyPEM); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	// Save certificate
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certFile.Close()

	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	}
	if err := pem.Encode(certFile, certPEM); err != nil {
		return fmt.Errorf("failed to encode certificate: %w", err)
	}

	log.Printf("Saved certificate and key to %s and %s", certPath, keyPath)
	return nil
}

// SetupNodeCertificates sets up complete certificate infrastructure for a node
func (m *MTLSCertificateManager) SetupNodeCertificates(nodeIdentity, caIdentity *NodeIdentity) (*MTLSConfig, error) {
	log.Printf("Setting up certificates for node: %s", nodeIdentity.NodeID)

	var caPrivateKey *rsa.PrivateKey
	var caCertificate *x509.Certificate
	var err error

	// Generate or load CA certificate
	if _, err := os.Stat(m.caKeyPath); os.IsNotExist(err) {
		log.Println("Generating new CA certificate")
		if caIdentity == nil {
			caIdentity = &NodeIdentity{
				NodeID:             fmt.Sprintf("ca-%s", nodeIdentity.NodeID),
				CommonName:         fmt.Sprintf("ECPS-CA-%s", nodeIdentity.Organization),
				Organization:       nodeIdentity.Organization,
				OrganizationalUnit: "Certificate Authority",
				Country:            nodeIdentity.Country,
				State:              nodeIdentity.State,
				Locality:           nodeIdentity.Locality,
				Email:              nodeIdentity.Email,
			}
		}

		caPrivateKey, caCertificate, err = m.GenerateCACertificate(caIdentity, 3650)
		if err != nil {
			return nil, fmt.Errorf("failed to generate CA certificate: %w", err)
		}

		if err := m.SaveCertificate(caPrivateKey, caCertificate, m.caKeyPath, m.caCertPath); err != nil {
			return nil, fmt.Errorf("failed to save CA certificate: %w", err)
		}
	} else {
		log.Println("Loading existing CA certificate")
		caPrivateKey, caCertificate, err = m.loadCACertificate()
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificate: %w", err)
		}
	}

	// Generate server certificate
	serverPrivateKey, serverCertificate, err := m.GenerateNodeCertificate(
		nodeIdentity, caPrivateKey, caCertificate, true, 365,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server certificate: %w", err)
	}

	if err := m.SaveCertificate(serverPrivateKey, serverCertificate, m.serverKeyPath, m.serverCertPath); err != nil {
		return nil, fmt.Errorf("failed to save server certificate: %w", err)
	}

	// Generate client certificate
	clientPrivateKey, clientCertificate, err := m.GenerateNodeCertificate(
		nodeIdentity, caPrivateKey, caCertificate, false, 365,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client certificate: %w", err)
	}

	if err := m.SaveCertificate(clientPrivateKey, clientCertificate, m.clientKeyPath, m.clientCertPath); err != nil {
		return nil, fmt.Errorf("failed to save client certificate: %w", err)
	}

	// Return mTLS configuration
	config := &MTLSConfig{
		CACertPath:     m.caCertPath,
		ServerCertPath: m.serverCertPath,
		ServerKeyPath:  m.serverKeyPath,
		ClientCertPath: m.clientCertPath,
		ClientKeyPath:  m.clientKeyPath,
		VerifyMode:     tls.RequireAndVerifyClientCert,
		CheckHostname:  true,
	}

	log.Println("Certificate setup completed successfully")
	return config, nil
}

// loadCACertificate loads CA private key and certificate from files
func (m *MTLSCertificateManager) loadCACertificate() (*rsa.PrivateKey, *x509.Certificate, error) {
	// Load private key
	keyData, err := ioutil.ReadFile(m.caKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	// Load certificate
	certData, err := ioutil.ReadFile(m.caCertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA cert: %w", err)
	}

	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA cert PEM")
	}

	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	return privateKey, certificate, nil
}

// MTLSTransport provides mTLS transport layer for ECPS communication
type MTLSTransport struct {
	config *MTLSConfig
}

// NewMTLSTransport creates a new mTLS transport
func NewMTLSTransport(config *MTLSConfig) *MTLSTransport {
	return &MTLSTransport{config: config}
}

// CreateServerTLSConfig creates TLS config for server connections
func (t *MTLSTransport) CreateServerTLSConfig() (*tls.Config, error) {
	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair(t.config.ServerCertPath, t.config.ServerKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	// Load CA certificate
	caCert, err := ioutil.ReadFile(t.config.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   t.config.VerifyMode,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	log.Println("Created server TLS config")
	return tlsConfig, nil
}

// CreateClientTLSConfig creates TLS config for client connections
func (t *MTLSTransport) CreateClientTLSConfig() (*tls.Config, error) {
	// Load client certificate and key
	clientCert, err := tls.LoadX509KeyPair(t.config.ClientCertPath, t.config.ClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	// Load CA certificate
	caCert, err := ioutil.ReadFile(t.config.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: !t.config.CheckHostname,
		MinVersion:         tls.VersionTLS12,
	}

	log.Println("Created client TLS config")
	return tlsConfig, nil
}

// CreateGRPCServerCredentials creates gRPC server credentials for mTLS
func (t *MTLSTransport) CreateGRPCServerCredentials() (credentials.TransportCredentials, error) {
	tlsConfig, err := t.CreateServerTLSConfig()
	if err != nil {
		return nil, err
	}

	creds := credentials.NewTLS(tlsConfig)
	log.Println("Created gRPC server credentials")
	return creds, nil
}

// CreateGRPCClientCredentials creates gRPC client credentials for mTLS
func (t *MTLSTransport) CreateGRPCClientCredentials() (credentials.TransportCredentials, error) {
	tlsConfig, err := t.CreateClientTLSConfig()
	if err != nil {
		return nil, err
	}

	creds := credentials.NewTLS(tlsConfig)
	log.Println("Created gRPC client credentials")
	return creds, nil
}

// VerifyPeerCertificate verifies peer certificate against CA
func (t *MTLSTransport) VerifyPeerCertificate(peerCert *x509.Certificate) error {
	// Load CA certificate
	caCertData, err := ioutil.ReadFile(t.config.CACertPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertBlock, _ := pem.Decode(caCertData)
	if caCertBlock == nil {
		return fmt.Errorf("failed to decode CA certificate")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Create certificate pool with CA
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// Verify certificate
	opts := x509.VerifyOptions{Roots: roots}
	if _, err := peerCert.Verify(opts); err != nil {
		return fmt.Errorf("peer certificate verification failed: %w", err)
	}

	// Check validity period
	now := time.Now()
	if now.Before(peerCert.NotBefore) || now.After(peerCert.NotAfter) {
		return fmt.Errorf("peer certificate is not within validity period")
	}

	log.Println("Peer certificate verification successful")
	return nil
}

// Global mTLS transport instance
var globalMTLSTransport *MTLSTransport

// InitializeMTLS initializes mTLS for the current node
func InitializeMTLS(nodeIdentity *NodeIdentity, certDir string, caIdentity *NodeIdentity) (*MTLSConfig, error) {
	certManager := NewMTLSCertificateManager(certDir)
	config, err := certManager.SetupNodeCertificates(nodeIdentity, caIdentity)
	if err != nil {
		return nil, err
	}

	globalMTLSTransport = NewMTLSTransport(config)
	log.Printf("mTLS initialized for node: %s", nodeIdentity.NodeID)
	return config, nil
}

// GetMTLSTransport returns the global mTLS transport instance
func GetMTLSTransport() *MTLSTransport {
	return globalMTLSTransport
}
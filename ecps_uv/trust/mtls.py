"""
Mutual TLS (mTLS) Implementation for ECPS-UV SDK.

This module provides mTLS authentication and encryption between ECPS nodes,
ensuring secure communication in distributed robotic systems.
"""

import asyncio
import logging
import os
import ssl
import socket
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, List, Any, Callable
from dataclasses import dataclass
from pathlib import Path
import aiofiles
import aiohttp
import grpc
from grpc import aio as aio_grpc

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

logger = logging.getLogger("ecps_uv.trust.mtls")


@dataclass
class MTLSConfig:
    """Configuration for mTLS setup."""
    ca_cert_path: str
    server_cert_path: str
    server_key_path: str
    client_cert_path: str
    client_key_path: str
    verify_mode: ssl.VerifyMode = ssl.CERT_REQUIRED
    check_hostname: bool = True
    ciphers: Optional[str] = None
    protocol: ssl.Protocol = ssl.PROTOCOL_TLS
    cert_reqs: ssl.VerifyMode = ssl.CERT_REQUIRED


@dataclass
class NodeIdentity:
    """Identity information for an ECPS node."""
    node_id: str
    common_name: str
    organization: str
    organizational_unit: str
    country: str
    state: str
    locality: str
    email: Optional[str] = None
    dns_names: List[str] = None
    ip_addresses: List[str] = None


class MTLSCertificateManager:
    """Manages mTLS certificates for ECPS nodes."""
    
    def __init__(self, cert_dir: str = None):
        """
        Initialize certificate manager.
        
        Args:
            cert_dir: Directory to store certificates
        """
        self.cert_dir = Path(cert_dir or os.path.join(os.path.expanduser("~"), ".ecps", "certs"))
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        
        # Certificate paths
        self.ca_key_path = self.cert_dir / "ca-key.pem"
        self.ca_cert_path = self.cert_dir / "ca-cert.pem"
        self.server_key_path = self.cert_dir / "server-key.pem"
        self.server_cert_path = self.cert_dir / "server-cert.pem"
        self.client_key_path = self.cert_dir / "client-key.pem"
        self.client_cert_path = self.cert_dir / "client-cert.pem"
        
        logger.info(f"Certificate manager initialized with cert_dir: {self.cert_dir}")
    
    def generate_ca_certificate(
        self,
        identity: NodeIdentity,
        validity_days: int = 3650
    ) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """
        Generate a Certificate Authority (CA) certificate.
        
        Args:
            identity: CA identity information
            validity_days: Certificate validity period in days
            
        Returns:
            (private_key, certificate): CA private key and certificate
        """
        logger.info(f"Generating CA certificate for {identity.common_name}")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, identity.country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, identity.state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, identity.locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, identity.organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, identity.organizational_unit),
            x509.NameAttribute(NameOID.COMMON_NAME, identity.common_name),
        ])
        
        if identity.email:
            subject = x509.Name(list(subject) + [
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, identity.email)
            ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(identity.common_name),
            ]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                key_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).sign(private_key, hashes.SHA256())
        
        logger.info(f"Generated CA certificate with serial: {cert.serial_number}")
        return private_key, cert
    
    def generate_node_certificate(
        self,
        identity: NodeIdentity,
        ca_private_key: rsa.RSAPrivateKey,
        ca_certificate: x509.Certificate,
        is_server: bool = True,
        validity_days: int = 365
    ) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """
        Generate a node certificate signed by the CA.
        
        Args:
            identity: Node identity information
            ca_private_key: CA private key for signing
            ca_certificate: CA certificate
            is_server: Whether this is a server certificate
            validity_days: Certificate validity period in days
            
        Returns:
            (private_key, certificate): Node private key and certificate
        """
        cert_type = "server" if is_server else "client"
        logger.info(f"Generating {cert_type} certificate for {identity.common_name}")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, identity.country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, identity.state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, identity.locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, identity.organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, identity.organizational_unit),
            x509.NameAttribute(NameOID.COMMON_NAME, identity.common_name),
        ])
        
        if identity.email:
            subject = x509.Name(list(subject) + [
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, identity.email)
            ])
        
        # Build certificate
        cert_builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_certificate.subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        )
        
        # Add Subject Alternative Names
        san_list = []
        if identity.dns_names:
            san_list.extend([x509.DNSName(name) for name in identity.dns_names])
        if identity.ip_addresses:
            san_list.extend([x509.IPAddress(ip) for ip in identity.ip_addresses])
        
        # Always include the common name as a DNS name
        san_list.append(x509.DNSName(identity.common_name))
        
        if san_list:
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )
        
        # Add key usage
        if is_server:
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    key_cert_sign=False,
                    crl_sign=False,
                    digital_signature=True,
                    key_encipherment=True,
                    key_agreement=False,
                    content_commitment=False,
                    data_encipherment=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.SERVER_AUTH,
                ]),
                critical=True,
            )
        else:
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    key_cert_sign=False,
                    crl_sign=False,
                    digital_signature=True,
                    key_encipherment=True,
                    key_agreement=False,
                    content_commitment=False,
                    data_encipherment=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=True,
            )
        
        # Sign the certificate
        cert = cert_builder.sign(ca_private_key, hashes.SHA256())
        
        logger.info(f"Generated {cert_type} certificate with serial: {cert.serial_number}")
        return private_key, cert
    
    async def save_certificate(
        self,
        private_key: rsa.RSAPrivateKey,
        certificate: x509.Certificate,
        key_path: Path,
        cert_path: Path
    ) -> None:
        """
        Save private key and certificate to files.
        
        Args:
            private_key: Private key to save
            certificate: Certificate to save
            key_path: Path to save private key
            cert_path: Path to save certificate
        """
        # Save private key
        key_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
        
        async with aiofiles.open(key_path, 'wb') as f:
            await f.write(key_pem)
        
        # Set restrictive permissions on private key
        os.chmod(key_path, 0o600)
        
        # Save certificate
        cert_pem = certificate.public_bytes(Encoding.PEM)
        
        async with aiofiles.open(cert_path, 'wb') as f:
            await f.write(cert_pem)
        
        logger.info(f"Saved certificate and key to {cert_path} and {key_path}")
    
    async def setup_node_certificates(
        self,
        node_identity: NodeIdentity,
        ca_identity: Optional[NodeIdentity] = None
    ) -> MTLSConfig:
        """
        Set up complete certificate infrastructure for a node.
        
        Args:
            node_identity: Identity for the node
            ca_identity: Identity for CA (if None, uses node_identity)
            
        Returns:
            MTLSConfig with paths to generated certificates
        """
        logger.info(f"Setting up certificates for node: {node_identity.node_id}")
        
        # Use node identity for CA if not provided
        if ca_identity is None:
            ca_identity = NodeIdentity(
                node_id=f"ca-{node_identity.node_id}",
                common_name=f"ECPS-CA-{node_identity.organization}",
                organization=node_identity.organization,
                organizational_unit="Certificate Authority",
                country=node_identity.country,
                state=node_identity.state,
                locality=node_identity.locality,
                email=node_identity.email
            )
        
        # Generate CA certificate if it doesn't exist
        if not (self.ca_key_path.exists() and self.ca_cert_path.exists()):
            logger.info("Generating new CA certificate")
            ca_private_key, ca_certificate = self.generate_ca_certificate(ca_identity)
            await self.save_certificate(ca_private_key, ca_certificate, self.ca_key_path, self.ca_cert_path)
        else:
            logger.info("Loading existing CA certificate")
            async with aiofiles.open(self.ca_key_path, 'rb') as f:
                ca_key_pem = await f.read()
            ca_private_key = serialization.load_pem_private_key(ca_key_pem, password=None)
            
            async with aiofiles.open(self.ca_cert_path, 'rb') as f:
                ca_cert_pem = await f.read()
            ca_certificate = x509.load_pem_x509_certificate(ca_cert_pem)
        
        # Generate server certificate
        server_private_key, server_certificate = self.generate_node_certificate(
            node_identity, ca_private_key, ca_certificate, is_server=True
        )
        await self.save_certificate(
            server_private_key, server_certificate, self.server_key_path, self.server_cert_path
        )
        
        # Generate client certificate
        client_private_key, client_certificate = self.generate_node_certificate(
            node_identity, ca_private_key, ca_certificate, is_server=False
        )
        await self.save_certificate(
            client_private_key, client_certificate, self.client_key_path, self.client_cert_path
        )
        
        # Return mTLS configuration
        config = MTLSConfig(
            ca_cert_path=str(self.ca_cert_path),
            server_cert_path=str(self.server_cert_path),
            server_key_path=str(self.server_key_path),
            client_cert_path=str(self.client_cert_path),
            client_key_path=str(self.client_key_path)
        )
        
        logger.info("Certificate setup completed successfully")
        return config


class MTLSTransport:
    """mTLS transport layer for ECPS communication."""
    
    def __init__(self, config: MTLSConfig):
        """
        Initialize mTLS transport.
        
        Args:
            config: mTLS configuration
        """
        self.config = config
        self._ssl_context_server: Optional[ssl.SSLContext] = None
        self._ssl_context_client: Optional[ssl.SSLContext] = None
        
        logger.info("mTLS transport initialized")
    
    def create_server_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for server connections."""
        if self._ssl_context_server is None:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.verify_mode = self.config.verify_mode
            context.check_hostname = False  # We'll verify manually
            
            # Load server certificate and key
            context.load_cert_chain(
                self.config.server_cert_path,
                self.config.server_key_path
            )
            
            # Load CA certificate for client verification
            context.load_verify_locations(self.config.ca_cert_path)
            
            # Set cipher suites if specified
            if self.config.ciphers:
                context.set_ciphers(self.config.ciphers)
            
            self._ssl_context_server = context
            logger.debug("Created server SSL context")
        
        return self._ssl_context_server
    
    def create_client_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for client connections."""
        if self._ssl_context_client is None:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.verify_mode = self.config.verify_mode
            context.check_hostname = self.config.check_hostname
            
            # Load client certificate and key
            context.load_cert_chain(
                self.config.client_cert_path,
                self.config.client_key_path
            )
            
            # Load CA certificate for server verification
            context.load_verify_locations(self.config.ca_cert_path)
            
            # Set cipher suites if specified
            if self.config.ciphers:
                context.set_ciphers(self.config.ciphers)
            
            self._ssl_context_client = context
            logger.debug("Created client SSL context")
        
        return self._ssl_context_client
    
    def create_grpc_server_credentials(self) -> grpc.ServerCredentials:
        """Create gRPC server credentials for mTLS."""
        with open(self.config.ca_cert_path, 'rb') as f:
            ca_cert = f.read()
        
        with open(self.config.server_cert_path, 'rb') as f:
            server_cert = f.read()
        
        with open(self.config.server_key_path, 'rb') as f:
            server_key = f.read()
        
        credentials = grpc.ssl_server_credentials(
            [(server_key, server_cert)],
            root_certificates=ca_cert,
            require_client_auth=True
        )
        
        logger.debug("Created gRPC server credentials")
        return credentials
    
    def create_grpc_channel_credentials(self) -> grpc.ChannelCredentials:
        """Create gRPC channel credentials for mTLS."""
        with open(self.config.ca_cert_path, 'rb') as f:
            ca_cert = f.read()
        
        with open(self.config.client_cert_path, 'rb') as f:
            client_cert = f.read()
        
        with open(self.config.client_key_path, 'rb') as f:
            client_key = f.read()
        
        credentials = grpc.ssl_channel_credentials(
            root_certificates=ca_cert,
            private_key=client_key,
            certificate_chain=client_cert
        )
        
        logger.debug("Created gRPC channel credentials")
        return credentials
    
    async def create_aiohttp_connector(self) -> aiohttp.TCPConnector:
        """Create aiohttp connector with mTLS support."""
        ssl_context = self.create_client_ssl_context()
        
        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            limit=100,
            limit_per_host=30,
            ttl_dns_cache=300,
            use_dns_cache=True,
        )
        
        logger.debug("Created aiohttp connector with mTLS")
        return connector
    
    def verify_peer_certificate(self, peer_cert: x509.Certificate) -> bool:
        """
        Verify peer certificate against CA.
        
        Args:
            peer_cert: Peer certificate to verify
            
        Returns:
            True if certificate is valid
        """
        try:
            # Load CA certificate
            with open(self.config.ca_cert_path, 'rb') as f:
                ca_cert_pem = f.read()
            ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
            
            # Verify signature
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                peer_cert.signature,
                peer_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                peer_cert.signature_hash_algorithm
            )
            
            # Check validity period
            now = datetime.utcnow()
            if now < peer_cert.not_valid_before or now > peer_cert.not_valid_after:
                logger.warning("Peer certificate is not within validity period")
                return False
            
            logger.debug("Peer certificate verification successful")
            return True
            
        except Exception as e:
            logger.error(f"Peer certificate verification failed: {e}")
            return False


# Global mTLS transport instance
_mtls_transport: Optional[MTLSTransport] = None


async def initialize_mtls(
    node_identity: NodeIdentity,
    cert_dir: Optional[str] = None,
    ca_identity: Optional[NodeIdentity] = None
) -> MTLSConfig:
    """
    Initialize mTLS for the current node.
    
    Args:
        node_identity: Identity for this node
        cert_dir: Directory to store certificates
        ca_identity: Identity for CA (optional)
        
    Returns:
        mTLS configuration
    """
    global _mtls_transport
    
    cert_manager = MTLSCertificateManager(cert_dir)
    config = await cert_manager.setup_node_certificates(node_identity, ca_identity)
    
    _mtls_transport = MTLSTransport(config)
    
    logger.info(f"mTLS initialized for node: {node_identity.node_id}")
    return config


def get_mtls_transport() -> Optional[MTLSTransport]:
    """Get the global mTLS transport instance."""
    return _mtls_transport
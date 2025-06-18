# ECPS: Embodied Cognition Protocol Stack for Agent and Robot Communication

ECPS-UV is a complete, high-performance Python/Go implementation of the Embodied Cognition Protocol Stack (ECPS) specification, utilizing the UV library for asynchronous I/O operations.

## Overview

The Embodied Cognition Protocol Stack (ECPS) is a complete, transport-agnostic protocol stack designed to facilitate sophisticated communication between AI-agent/world-model cognitive cores and physical or simulated robotic systems. It provides a deterministic, replayable, and auditable communication backbone, enabling AI agents to perceive, remember, reason, and act without reliance on external "oracles."

This SDK implements the full ECPS v1.0 specification using Python with UV for high-performance async I/O, providing a complete solution for developing ECPS-compliant systems.

## Features

- **Complete Implementation**: All layers of the ECPS specification are implemented:
  - Transport Layer (L2): DDS/RTPS, gRPC/HTTP-2, MQTT 5
  - Serialization & Event Envelope (L3): Protocol Buffers, CloudEvents 1.0
  - Observability (L4): OpenTelemetry integration
  - Perception Data (L5): LTP for efficient tensor transmission
  - Cognition (L6): MCP for prompts, MEP for memory operations
  - Actuation (L7): EAP for robot control commands
  - Trust Layer: Cross-cutting security and authentication

- **Multiple Transport Bindings**:
  - DDS/RTPS for real-time local control
  - gRPC/HTTP-2 for cloud/WAN communication
  - MQTT 5 for constrained IoT devices

- **Conformance Profiles**:
  - Edge-Lite Profile for constrained environments
  - Standard Profile for typical development
  - Cloud-Fleet Profile for large-scale deployments

- **High Performance**: Built on UV for efficient async I/O and networking
  
- **Deterministic Replay**: Support for action logging and replay via `.eaplog` files

- **Comprehensive Security**:
  - Authentication via JWT and certificate-based mechanisms
  - Authorization with role-based access control (RBAC)
  - Message encryption and integrity verification
  - Graduated security levels for different deployment scenarios
  - Transparent security wrapper for all protocol layers

## Installation

```bash
pip install ecps-uv
```

For development installation:

```bash
git clone https://github.com/yourusername/ecps-uv.git
cd ecps-uv
pip install -e .
```

## Dependencies

- Python 3.8+
- UV
- Protocol Buffers
- gRPC
- Cyclone DDS
- Paho MQTT
- OpenTelemetry
- CloudEvents
- zstd
- NumPy
- PyJWT
- cryptography

## Quick Start

### Server Example

```python
import asyncio
import ecps_uv
from ecps_uv.core import StandardProfile

async def main():
    # Create server with Standard profile
    config = StandardProfile(transport_type="dds")
    server = ecps_uv.ECPSServer(config)
    
    # Define MCP handler
    async def handle_mcp(mcp_message):
        print(f"Received prompt: {mcp_message.prompt}")
    
    # Define EAP handler
    async def handle_eap(eap_message):
        if eap_message.HasField("set_pose"):
            pose = eap_message.set_pose
            print(f"Robot pose: x={pose.x}, y={pose.y}, z={pose.z}")
    
    # Register handlers
    server.on_mcp(handle_mcp)
    server.on_eap(handle_eap)
    
    # Start MEP service
    server.start_mep_service()
    
    # Start the server
    await server.start()
    
    # Keep server running
    try:
        while True:
            await asyncio.sleep(1)
    finally:
        await server.close()

if __name__ == "__main__":
    asyncio.run(main())
```

### Client Example

```python
import asyncio
import numpy as np
import ecps_uv
from ecps_uv.core import StandardProfile

async def main():
    # Create client with Standard profile
    config = StandardProfile(transport_type="dds")
    client = ecps_uv.ECPSClient(config)
    
    # Send MCP message
    prompt = "Move the robot arm to pick up the object"
    mcp_id = await client.send_mcp(prompt)
    print(f"Sent MCP message with ID: {mcp_id}")
    
    # Store memory embedding
    embedding = np.random.rand(1, 256).astype(np.float32)
    success, message = await client.store_memory(
        # LTP parameters would go here
    )
    
    # Send robot action
    pose_data = {
        "x": 0.5, "y": 0.3, "z": 0.2,
        "qw": 1.0, "qx": 0.0, "qy": 0.0, "qz": 0.0,
    }
    action_id = await client.send_action(
        action_type="set_pose",
        action_data=pose_data,
    )
    
    await client.close()

if __name__ == "__main__":
    asyncio.run(main())
```

## Complete Examples

For complete examples, check the `examples/` directory. In particular:

- `examples/ecps_demo.py`: Demonstrates basic functionality
- `examples/secure_ecps.py`: Shows how to use the trust layer for secure communication

## Architecture

The SDK is organized according to the ECPS layered model:

```
ecps_uv/
├── __init__.py          # Main package exports
├── core.py              # Client/Server implementations
├── transport/           # L2: Transport layer
│   ├── __init__.py
│   ├── base.py          # Transport interface
│   ├── dds.py           # DDS/RTPS binding
│   ├── grpc.py          # gRPC/HTTP-2 binding
│   └── mqtt.py          # MQTT 5 binding
├── serialization/       # L3: Serialization & envelope
│   ├── __init__.py
│   ├── protobuf.py      # Protocol Buffers serializer
│   └── cloudevents.py   # CloudEvents wrapper
├── observability/       # L4: Observability
│   ├── __init__.py
│   └── telemetry.py     # OpenTelemetry integration
├── perception/          # L5: Perception data
│   ├── __init__.py
│   └── ltp.py           # Latent Tensor Protocol
├── cognition/           # L6: Cognition
│   ├── __init__.py
│   ├── mcp.py           # Model Context Protocol
│   └── mep.py           # Memory Exchange Protocol
├── actuation/           # L7: Actuation
│   ├── __init__.py
│   └── eap.py           # Embodied Action Protocol
└── trust/               # Cross-cutting: Security
    ├── __init__.py
    ├── trust.py         # Trust provider and RBAC
    └── secure_transport.py # Secure message wrapper
```

## Roadmap

The ECPS UV SDK is under active development. Here's our roadmap for future enhancements:

### Near-term (Q3 2025)
- Add additional transport implementations (gRPC, MQTT)
- Enhance trust layer with hardware security module (HSM) integration
- Improve documentation and add comprehensive API references
- Add performance benchmarking tools and profiles

### Mid-term (Q4 2025)
- Implement transport auto-discovery and failover
- Add zero-copy optimizations for tensor operations
- Create a visualization tool for ECPS message flows
- Implement batch operations for improved efficiency
- Add support for additional serialization formats

### Long-term (2026)
- Support for federated trust models across multiple devices
- Advanced fleet management capabilities
- Enhanced security features (formal verification, compliance certifications)
- Support for embedded/constrained environments
- Cross-language interoperability testing framework

## Trust Layer Implementation

The ECPS SDK provides a comprehensive trust layer for securing communications across all protocol layers.

### Trust Layer Architecture

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#2a3950', 'primaryTextColor': '#f5f5f5', 'primaryBorderColor': '#4671a5', 'lineColor': '#a7c3e6', 'secondaryColor': '#3a506b', 'tertiaryColor': '#1e3a5f'}}}%%
flowchart TB
    BT["Base Transport"] --> ST
    ST --> ECPS["ECPS Protocols<br/>(LTP, MCP, MEP, EAP)"]
    TP --> Principals
    ID --> Identities
    Security --> TP
    
    subgraph TrustLayer["Trust Layer Components"]
        direction TB
        TP["TrustProvider<br/>(Authentication, Authorization)"]
        ST["SecureTransport<br/>(Message Security)"]
        RBAC["RBAC Authorizer<br/>(Permissions)"]
        ID["Identity Management<br/>(Users, Services, Devices)"]
        
        TP --- RBAC
        TP --- ID
        TP --- ST
    end
    
    subgraph Principals["Principal Management"]
        direction TB
        P1["Principal (Admin)"]
        P2["Principal (User)"]
        P3["Principal (Device)"]
        P4["Principal (Robot)"]
    end
    
    subgraph Identities["Identity Types"]
        direction TB
        I1["User Identity"]
        I2["Service Identity"]
        I3["Device Identity"]
        I4["Robot Identity"]
    end
    
    subgraph Security["Security Mechanisms"]
        direction TB
        S1["JWT Authentication"]
        S2["TLS Encryption"]
        S3["RSA Signatures"]
        S4["OAuth/OIDC"]
    end
    
    %% Styling
    classDef primary fill:#2a3950,stroke:#4671a5,color:#f5f5f5
    classDef secondary fill:#3a506b,stroke:#4671a5,color:#f5f5f5
    classDef tertiary fill:#1e3a5f,stroke:#4671a5,color:#f5f5f5
    classDef accent1 fill:#ff7e5f,stroke:#4671a5,color:#f5f5f5
    classDef accent2 fill:#6a89cc,stroke:#4671a5,color:#f5f5f5
    
    class TrustLayer,TP,RBAC primary
    class ST,Security,S1,S2,S3,S4 secondary
    class Principals,P1,P2,P3,P4 tertiary
    class Identities,I1,I2,I3,I4 accent1
    class ID,BT,ECPS accent2
```

### Security Levels

The trust layer implements graduated security levels to meet different deployment needs:

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#2a3950', 'primaryTextColor': '#f5f5f5', 'primaryBorderColor': '#4671a5', 'lineColor': '#a7c3e6', 'secondaryColor': '#3a506b', 'tertiaryColor': '#1e3a5f'}}}%%
graph TD
    NoSecurity["Level 0: None<br/>(No Security)"] --> Encryption["Level 1: Encryption<br/>(Message Privacy)"]
    Encryption --> Authentication["Level 2: Authentication<br/>(Identity Verification)"]
    Authentication --> Authorization["Level 3: Authorization<br/>(Permission Control)"]
    Authorization --> Auditing["Level 4: Auditing<br/>(Compliance Tracking)"]
    
    classDef none fill:#3a506b,stroke:#4671a5,color:#f5f5f5
    classDef enc fill:#1e3a5f,stroke:#4671a5,color:#f5f5f5
    classDef auth fill:#2a3950,stroke:#4671a5,color:#f5f5f5
    classDef authz fill:#6a89cc,stroke:#4671a5,color:#f5f5f5
    classDef audit fill:#ff7e5f,stroke:#4671a5,color:#f5f5f5
    
    class NoSecurity none
    class Encryption enc
    class Authentication auth
    class Authorization authz
    class Auditing audit
```

### Core Components

- **TrustProvider**: The central security service that manages authentication, authorization, and encryption
  - Supports multiple trust levels (None, Encryption, Authentication, Authorization, Auditing)
  - Handles key management (RSA) for cryptographic operations
  - Provides JWT token generation and validation
  - Manages principal identities with associated roles and permissions

- **Principal Model**: Representation of authenticated entities
  - Identity management with unique IDs
  - Role-based access control
  - Attribute-based policies
  - Fine-grained permissions for resources

- **SecureTransport**: Transparent security wrapper for any transport implementation
  - Message signing for integrity verification
  - Encryption for confidentiality
  - Authentication token handling
  - Principal validation

- **RBAC Authorizer**: Role-based access control implementation
  - Permission management by role
  - Action/resource permission model
  - Support for wildcard permissions
  - Integration with trust provider

- **Identity Management**: Complete identity system for managing authentication entities
  - Support for different identity types (User, Service, Device, Robot)
  - Credential storage and verification
  - Token generation and validation
  - Identity lifecycle management (create, update, disable, delete)
  - Association between identities and principals

### Identity Management

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#2a3950', 'primaryTextColor': '#f5f5f5', 'primaryBorderColor': '#4671a5', 'lineColor': '#a7c3e6', 'secondaryColor': '#3a506b', 'tertiaryColor': '#1e3a5f'}}}%%
sequenceDiagram
    participant C as Client
    participant IS as IdentityStore
    participant IP as IdentityProvider
    participant TP as TrustProvider
    
    Note over C,TP: Identity Creation
    C->>IS: create_identity(name, type, attributes)
    IS-->>C: Identity
    C->>IS: set_credential(identity_id, credential)
    C->>IS: associate_principal(identity_id, principal_id)
    
    Note over C,TP: Authentication Flow
    C->>IP: authenticate(identity_id, credential)
    IP->>IS: verify_credential(identity_id, credential)
    IS-->>IP: true/false
    IP-->>C: Identity or Error
    
    Note over C,TP: Token Generation
    C->>IP: create_identity_token(identity)
    IP-->>C: JWT Token
    
    Note over C,TP: Authorization
    C->>IP: identity_to_principal(identity)
    IP->>IS: get_principal_id(identity_id)
    IS-->>IP: principal_id
    IP->>TP: get_principal(principal_id)
    TP-->>IP: Principal
    IP-->>C: Principal
    C->>TP: authorize(principal, action, resource)
    TP-->>C: Authorized/Denied
```

The ECPS SDK provides a comprehensive identity management system that works with the trust layer:

```python
from ecps_uv.trust import (
    Identity, IdentityStore, IdentityProvider, IdentityType,
    create_default_identity_provider
)

# Create identity store and provider
identity_store = IdentityStore()
identity_provider = IdentityProvider(
    identity_store=identity_store,
    jwt_secret="your-secret-key",
)

# Create different types of identities
user = identity_store.create_identity(
    name="John Doe",
    type=IdentityType.USER,
    attributes={"email": "john@example.com"},
)
identity_store.set_credential(user.id, "user-password")
identity_store.associate_principal(user.id, "user1")

# Authenticate an identity
identity = await identity_provider.authenticate(user.id, "user-password")
if identity:
    # Create identity token
    token = identity_provider.create_identity_token(identity)
    
    # Get associated principal
    principal_id = await identity_provider.identity_to_principal(identity)
```

For a complete example, see `examples/identity_management_demo.py`.

### Python Decorator API

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#2a3950', 'primaryTextColor': '#f5f5f5', 'primaryBorderColor': '#4671a5', 'lineColor': '#a7c3e6', 'secondaryColor': '#3a506b', 'tertiaryColor': '#1e3a5f'}}}%%
flowchart LR
    subgraph Decorators["Security Decorators"]
        direction TB
        D1["@requires_authentication"]
        D2["@requires_authorization"]
        D3["@secure_operation"]
    end
    
    subgraph Functions["Protected Functions"]
        direction TB
        F1["get_user_profile()"]
        F2["read_sensor_data()"]
        F3["update_config()"]
    end
    
    subgraph Flow["Authentication Flow"]
        direction TB
        Auth["Authentication"]
        Authz["Authorization"]
        Exec["Function Execution"]
        Error["Error Handling"]
    end
    
    D1 --> F1
    D2 --> F2
    D3 --> F3
    
    User --> D1
    User --> D2
    User --> D3
    
    D1 --> Auth
    D2 --> Auth --> Authz
    D3 --> Auth --> Authz
    
    Auth --> Error
    Authz --> Error
    Auth --> Exec
    Authz --> Exec
    
    classDef decorator fill:#2a3950,stroke:#4671a5,color:#f5f5f5
    classDef function fill:#3a506b,stroke:#4671a5,color:#f5f5f5
    classDef flow fill:#1e3a5f,stroke:#4671a5,color:#f5f5f5
    classDef error fill:#ff7e5f,stroke:#4671a5,color:#f5f5f5
    classDef user fill:#6a89cc,stroke:#4671a5,color:#f5f5f5
    
    class Decorators,D1,D2,D3 decorator
    class Functions,F1,F2,F3 function
    class Auth,Authz,Exec flow
    class Error error
    class User user
```

The Python SDK provides a powerful decorator-based security API that makes it easy to add authentication and authorization checks to any function:

```python
from ecps_uv.trust import (
    requires_authentication,
    requires_authorization,
    secure_operation,
    AuthenticationError,
    AuthorizationError,
)

# Authentication only
@requires_authentication(trust_provider)
async def get_user_profile(principal):
    # Only executed if principal is authenticated
    return {...}

# Authorization check
@requires_authorization(trust_provider, "read", "sensor_data")
async def read_sensor_data(principal, sensor_id):
    # Only executed if principal can "read" on "sensor_data"
    return {...}

# Combined decorator for convenience
@secure_operation(trust_provider, "write", "config")
async def update_config(principal, config_name, value):
    # Only executed if principal can "write" on "config"
    return {...}
```

The decorators work with both synchronous and asynchronous functions and handle:
- Principal authentication
- Permission checking
- Proper error handling with descriptive exceptions
- Converting string IDs to principal objects automatically

For a complete example, see `examples/trust_decorators_demo.py`.

### Basic Usage Examples

```python
# Setting up a trust provider with authentication and authorization
trust_provider = TrustProvider(
    trust_level=TrustLevel.AUTHORIZATION,
    mechanisms=[TrustMechanism.JWT, TrustMechanism.TLS],
    jwt_secret="your-secret-key",
    private_key_path="path/to/private_key.pem",
    public_key_path="path/to/public_key.pem",
)

# Creating and adding a principal
admin_principal = Principal(
    id="admin1",
    name="Administrator",
    roles=["admin"],
    permissions={"publish:topic": True},
    attributes={"department": "IT"},
)
trust_provider.add_principal(admin_principal)

# Creating a secure transport
base_transport = DDSTransport()
secure_transport = trust_provider.secure_transport(base_transport)

# Using the secure transport with MCP
mcp_handler = MCPHandler(secure_transport, serializer, None)
```

For a complete example, see `examples/secure_ecps.py`.

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

# Identity Forwarding in ECPS UV SDK

## Overview

The ECPS UV SDK implements an **Identity Forwarding** system that provides a more efficient alternative to per-request signing for authentication and authorization in high-throughput scenarios.

## Problem with Per-Request Signing

Traditional secure communication systems sign every individual request, which creates several performance bottlenecks:

- **High CPU Overhead**: Cryptographic signing operations are computationally expensive
- **Network Overhead**: Digital signatures add significant payload size
- **Latency Impact**: Each request must wait for signing completion
- **Scalability Issues**: Performance degrades linearly with request volume

## Identity Forwarding Solution

Instead of signing every request, the Identity Forwarding system:

1. **Authenticates once** during session establishment
2. **Creates an identity context** with session-based credentials
3. **Forwards the identity context** through request chains
4. **Validates context** at each service hop without re-authentication

## Key Components

### IdentityContext

Represents an authenticated identity session that can be forwarded:

```python
@dataclass
class IdentityContext:
    identity: Identity              # The authenticated identity
    principal_id: str              # Associated principal ID
    session_id: str                # Unique session identifier
    established_at: datetime       # When context was created
    expires_at: datetime           # When context expires
    capabilities: Set[str]         # Granted capabilities
    attributes: Dict[str, Any]     # Additional context data
```

### ForwardedRequest

A request wrapper that carries identity context instead of signatures:

```python
@dataclass
class ForwardedRequest:
    payload: Any                   # Original request data
    identity_context: IdentityContext  # Forwarded identity
    request_id: str                # Unique request identifier
    timestamp: datetime            # Request creation time
    service_chain: List[str]       # Services in forwarding chain
```

### IdentityForwardingManager

Manages the lifecycle of identity contexts and request forwarding:

```python
class IdentityForwardingManager:
    async def establish_identity_context(...)  # Create session
    def create_forwarded_request(...)          # Wrap requests
    async def validate_forwarded_request(...)  # Validate at hops
    async def authorize_forwarded_request(...) # Authorize actions
    def refresh_context(...)                   # Extend sessions
    def revoke_context(...)                    # Terminate sessions
```

## Usage Examples

### 1. Establishing Identity Context

```python
# Create identity forwarding manager
forwarding_manager = create_default_identity_forwarding_manager(
    identity_provider, trust_provider
)

# Establish identity context (replaces per-request authentication)
identity_context = await forwarding_manager.establish_identity_context(
    identity_id="user-123",
    credential="password",
    capabilities={"read", "write", "coordinate"},
    session_duration=timedelta(hours=8),
)
```

### 2. Creating Forwarded Requests

```python
# Create a request with forwarded identity
forwarded_request = forwarding_manager.create_forwarded_request(
    payload={"action": "move_robot", "position": [100, 200, 50]},
    identity_context=identity_context,
)

# Send through transport (no signing required)
await transport.publish("robot_commands", forwarded_request.to_dict())
```

### 3. Validating Forwarded Requests

```python
# At receiving service
async def handle_robot_command(forwarded_dict: Dict[str, Any]):
    # Reconstruct forwarded request
    forwarded_request = ForwardedRequest.from_dict(forwarded_dict)
    
    # Validate identity context
    is_valid, error = await forwarding_manager.validate_forwarded_request(
        forwarded_request,
        required_capability="coordinate",
        service_name="robot_control_service",
    )
    
    if not is_valid:
        logger.error(f"Request validation failed: {error}")
        return
    
    # Authorize action
    authorized, reason = await forwarding_manager.authorize_forwarded_request(
        forwarded_request,
        action="control_robot",
        resource="robot_arm_1",
    )
    
    if not authorized:
        logger.error(f"Request authorization failed: {reason}")
        return
    
    # Process the actual payload
    await process_robot_command(forwarded_request.payload)
```

### 4. Service Chain Forwarding

```python
# Request passes through multiple services automatically
original_request = create_forwarded_request(payload, identity_context)

# Service 1: Data Ingestion
await validate_forwarded_request(original_request, "process", "ingestion")

# Service 2: Data Processing  
await validate_forwarded_request(original_request, "process", "processing")

# Service 3: Result Storage
await validate_forwarded_request(original_request, "store", "storage")

# Final service chain: ["ingestion", "processing", "storage"]
print(original_request.service_chain)
```

## Integration with Secure Transport

The `SecureTransport` class has been updated to use identity forwarding:

```python
# Create secure transport with identity forwarding
secure_transport = SecureTransport(
    transport=mqtt_transport,
    trust_provider=trust_provider,
    identity_forwarding_manager=forwarding_manager,
)

# Set identity context (replaces principal_id/security_token)
secure_transport.set_identity_context(identity_context)

# All subsequent operations use forwarded identity
await secure_transport.publish("topic", message)  # No signing!
```

## Performance Benefits

### Traditional Per-Request Signing
- ❌ **CPU**: High cryptographic overhead per request
- ❌ **Network**: Large signature payloads
- ❌ **Latency**: Signing delay on each request
- ❌ **Throughput**: Limited by signing performance

### Identity Forwarding
- ✅ **CPU**: Minimal overhead after session establishment
- ✅ **Network**: Compact identity context (no signatures)
- ✅ **Latency**: No per-request cryptographic operations
- ✅ **Throughput**: Scales with network/processing capacity

## Security Properties

### Session-Based Security
- **Authentication**: Performed once during context establishment
- **Authorization**: Validated at each service hop using forwarded context
- **Expiration**: Contexts have configurable time-based expiration
- **Revocation**: Contexts can be immediately revoked if compromised

### Capability-Based Access Control
- **Fine-Grained**: Capabilities can be specific to operations/resources
- **Least Privilege**: Only required capabilities are granted
- **Dynamic**: Capabilities can be added/removed during session

### Audit Trail
- **Request Tracking**: Each forwarded request has unique ID
- **Service Chain**: Complete path through services is recorded
- **Context Lifecycle**: Establishment, refresh, and revocation events

## Configuration

### Session Duration
```python
# Short-lived sessions for high-security environments
identity_context = await establish_identity_context(
    session_duration=timedelta(minutes=30)
)

# Long-lived sessions for development/testing
identity_context = await establish_identity_context(
    session_duration=timedelta(hours=24)
)
```

### Capability Management
```python
# Grant specific capabilities
capabilities = {"read:sensors", "write:actuators", "coordinate:robots"}

# Runtime capability management
identity_context.add_capability("admin:system")
identity_context.remove_capability("write:actuators")
```

### Context Refresh
```python
# Extend session lifetime
forwarding_manager.refresh_context(
    session_id=identity_context.session_id,
    additional_duration=timedelta(hours=4)
)
```

## Migration from Per-Request Signing

### Before (Per-Request Signing)
```python
# Every request requires signing
for request in requests:
    signature = trust_provider.sign_message(request)
    secure_msg = SecureMessage(message=request, signature=signature)
    await transport.publish(topic, secure_msg)
```

### After (Identity Forwarding)
```python
# Authenticate once
identity_context = await establish_identity_context(...)

# Forward identity with all requests
for request in requests:
    forwarded_request = create_forwarded_request(request, identity_context)
    await transport.publish(topic, forwarded_request)  # No signing!
```

## Best Practices

### 1. Session Management
- Use appropriate session durations for your security requirements
- Implement session refresh for long-running operations
- Revoke sessions immediately when users/services are deactivated

### 2. Capability Design
- Use specific, granular capabilities rather than broad permissions
- Follow principle of least privilege
- Regularly audit and review granted capabilities

### 3. Service Chain Validation
- Validate forwarded requests at every service hop
- Log service chain information for audit purposes
- Implement circuit breakers for invalid request patterns

### 4. Error Handling
- Gracefully handle expired contexts
- Provide clear error messages for validation failures
- Implement fallback mechanisms for critical operations

## Go Implementation

The Go implementation provides equivalent functionality with idiomatic Go patterns:

```go
// Establish identity context
identityContext, err := forwardingManager.EstablishIdentityContext(
    ctx, "user-123", "password", capabilities, &sessionDuration,
)

// Create forwarded request
forwardedRequest := forwardingManager.CreateForwardedRequest(
    payload, identityContext,
)

// Validate forwarded request
isValid, errorReason := forwardingManager.ValidateForwardedRequest(
    ctx, forwardedRequest, "coordinate", "robot_service",
)
```

## Conclusion

Identity Forwarding provides a significant performance improvement over per-request signing while maintaining strong security properties. It's particularly beneficial for:

- **High-throughput systems** with many requests per second
- **Microservice architectures** with complex service chains
- **Real-time systems** where latency is critical
- **Resource-constrained environments** where CPU usage matters

The system maintains backward compatibility with existing secure transport mechanisms while providing a more efficient path forward for modern distributed systems.
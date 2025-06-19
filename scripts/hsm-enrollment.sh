#!/bin/bash
# HSM/TPM Enrollment Script for ECPS-UV SDK
# This script sets up Hardware Security Module (HSM) or Trusted Platform Module (TPM)
# integration for secure key storage and cryptographic operations.

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ECPS_HOME="${ECPS_HOME:-$HOME/.ecps}"
HSM_CONFIG_DIR="$ECPS_HOME/hsm"
TPM_CONFIG_DIR="$ECPS_HOME/tpm"
LOG_FILE="$ECPS_HOME/enrollment.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        warning "Running as root. This may not be necessary for all operations."
    fi
}

# Create necessary directories
setup_directories() {
    log "Setting up directories..."
    mkdir -p "$ECPS_HOME" "$HSM_CONFIG_DIR" "$TPM_CONFIG_DIR"
    chmod 700 "$ECPS_HOME" "$HSM_CONFIG_DIR" "$TPM_CONFIG_DIR"
    success "Directories created"
}

# Check system dependencies
check_dependencies() {
    log "Checking system dependencies..."
    
    local missing_deps=()
    
    # Check for OpenSSL
    if ! command -v openssl &> /dev/null; then
        missing_deps+=("openssl")
    fi
    
    # Check for pkcs11-tool (for HSM)
    if ! command -v pkcs11-tool &> /dev/null; then
        missing_deps+=("opensc")
    fi
    
    # Check for tpm2-tools (for TPM)
    if ! command -v tpm2_createprimary &> /dev/null; then
        missing_deps+=("tpm2-tools")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        warning "Missing dependencies: ${missing_deps[*]}"
        log "Install with: sudo apt-get install ${missing_deps[*]} (Ubuntu/Debian)"
        log "Or: sudo yum install ${missing_deps[*]} (RHEL/CentOS)"
        log "Or: brew install ${missing_deps[*]} (macOS)"
    else
        success "All dependencies found"
    fi
}

# Detect available HSM devices
detect_hsm() {
    log "Detecting HSM devices..."
    
    local hsm_found=false
    
    # Check for SoftHSM (software HSM for testing)
    if command -v softhsm2-util &> /dev/null; then
        log "Found SoftHSM2"
        echo "softhsm2" > "$HSM_CONFIG_DIR/detected_hsm"
        hsm_found=true
    fi
    
    # Check for PKCS#11 libraries
    local pkcs11_libs=(
        "/usr/lib/softhsm/libsofthsm2.so"
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
        "/usr/local/lib/softhsm/libsofthsm2.so"
        "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so"
        "/usr/lib/libykcs11.so"
    )
    
    for lib in "${pkcs11_libs[@]}"; do
        if [[ -f "$lib" ]]; then
            log "Found PKCS#11 library: $lib"
            echo "$lib" >> "$HSM_CONFIG_DIR/pkcs11_libraries"
            hsm_found=true
        fi
    done
    
    if [[ "$hsm_found" == true ]]; then
        success "HSM devices detected"
    else
        warning "No HSM devices detected"
    fi
}

# Detect TPM
detect_tpm() {
    log "Detecting TPM..."
    
    local tpm_found=false
    
    # Check for TPM device files
    if [[ -c /dev/tpm0 ]] || [[ -c /dev/tpmrm0 ]]; then
        log "Found TPM device"
        tpm_found=true
    fi
    
    # Check TPM version
    if command -v tpm2_getcap &> /dev/null; then
        if tpm2_getcap properties-fixed 2>/dev/null | grep -q "TPM2"; then
            log "TPM 2.0 detected"
            echo "2.0" > "$TPM_CONFIG_DIR/tpm_version"
            tpm_found=true
        fi
    fi
    
    # Check for TPM simulator
    if pgrep -f "tpm_server\|swtpm" &> /dev/null; then
        log "TPM simulator detected"
        echo "simulator" > "$TPM_CONFIG_DIR/tpm_type"
        tpm_found=true
    fi
    
    if [[ "$tpm_found" == true ]]; then
        success "TPM detected"
    else
        warning "No TPM detected"
    fi
}

# Setup SoftHSM for testing
setup_softhsm() {
    log "Setting up SoftHSM for testing..."
    
    if ! command -v softhsm2-util &> /dev/null; then
        error "SoftHSM2 not found. Please install it first."
    fi
    
    local token_dir="$HSM_CONFIG_DIR/softhsm_tokens"
    local config_file="$HSM_CONFIG_DIR/softhsm2.conf"
    
    mkdir -p "$token_dir"
    chmod 700 "$token_dir"
    
    # Create SoftHSM configuration
    cat > "$config_file" << EOF
# SoftHSM v2 configuration file for ECPS
directories.tokendir = $token_dir
objectstore.backend = file
log.level = INFO
slots.removable = false
EOF
    
    export SOFTHSM2_CONF="$config_file"
    
    # Initialize token
    local token_label="ecps-token"
    local so_pin="123456"
    local user_pin="654321"
    
    log "Initializing SoftHSM token..."
    softhsm2-util --init-token --slot 0 --label "$token_label" --so-pin "$so_pin" --pin "$user_pin"
    
    # Save configuration
    cat > "$HSM_CONFIG_DIR/softhsm_config.json" << EOF
{
    "token_label": "$token_label",
    "so_pin": "$so_pin",
    "user_pin": "$user_pin",
    "config_file": "$config_file",
    "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so"
}
EOF
    
    chmod 600 "$HSM_CONFIG_DIR/softhsm_config.json"
    success "SoftHSM setup completed"
}

# Generate HSM key pair
generate_hsm_keypair() {
    log "Generating HSM key pair..."
    
    if [[ ! -f "$HSM_CONFIG_DIR/softhsm_config.json" ]]; then
        error "SoftHSM not configured. Run setup_softhsm first."
    fi
    
    local config=$(cat "$HSM_CONFIG_DIR/softhsm_config.json")
    local token_label=$(echo "$config" | jq -r '.token_label')
    local user_pin=$(echo "$config" | jq -r '.user_pin')
    local pkcs11_lib=$(echo "$config" | jq -r '.pkcs11_library')
    
    export SOFTHSM2_CONF="$HSM_CONFIG_DIR/softhsm2.conf"
    
    # Generate RSA key pair
    pkcs11-tool --module "$pkcs11_lib" --login --pin "$user_pin" \
        --keypairgen --key-type rsa:2048 --label "ecps-signing-key" --id 01
    
    # Generate another key pair for encryption
    pkcs11-tool --module "$pkcs11_lib" --login --pin "$user_pin" \
        --keypairgen --key-type rsa:2048 --label "ecps-encryption-key" --id 02
    
    success "HSM key pairs generated"
}

# Setup TPM
setup_tpm() {
    log "Setting up TPM..."
    
    if ! command -v tpm2_createprimary &> /dev/null; then
        error "TPM2 tools not found. Please install tpm2-tools."
    fi
    
    local tpm_dir="$TPM_CONFIG_DIR"
    
    # Clear TPM (optional, for testing)
    if [[ "${CLEAR_TPM:-false}" == "true" ]]; then
        warning "Clearing TPM..."
        tpm2_clear -c platform
    fi
    
    # Create primary key
    log "Creating TPM primary key..."
    tpm2_createprimary -C e -g sha256 -G rsa -c "$tmp_dir/primary.ctx"
    
    # Create signing key
    log "Creating TPM signing key..."
    tpm2_create -g sha256 -G rsa -u "$tpm_dir/signing.pub" -r "$tpm_dir/signing.priv" -C "$tpm_dir/primary.ctx"
    
    # Create encryption key
    log "Creating TPM encryption key..."
    tpm2_create -g sha256 -G rsa -u "$tpm_dir/encryption.pub" -r "$tpm_dir/encryption.priv" -C "$tpm_dir/primary.ctx"
    
    # Load keys
    tpm2_load -C "$tpm_dir/primary.ctx" -u "$tpm_dir/signing.pub" -r "$tpm_dir/signing.priv" -c "$tpm_dir/signing.ctx"
    tpm2_load -C "$tpm_dir/primary.ctx" -u "$tpm_dir/encryption.pub" -r "$tpm_dir/encryption.priv" -c "$tmp_dir/encryption.ctx"
    
    # Make keys persistent
    tpm2_evictcontrol -C o -c "$tpm_dir/signing.ctx" 0x81000001
    tpm2_evictcontrol -C o -c "$tpm_dir/encryption.ctx" 0x81000002
    
    # Save configuration
    cat > "$tpm_dir/tpm_config.json" << EOF
{
    "signing_handle": "0x81000001",
    "encryption_handle": "0x81000002",
    "primary_context": "$tpm_dir/primary.ctx",
    "setup_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
    
    success "TPM setup completed"
}

# Test HSM functionality
test_hsm() {
    log "Testing HSM functionality..."
    
    if [[ ! -f "$HSM_CONFIG_DIR/softhsm_config.json" ]]; then
        warning "SoftHSM not configured. Skipping HSM test."
        return
    fi
    
    local config=$(cat "$HSM_CONFIG_DIR/softhsm_config.json")
    local user_pin=$(echo "$config" | jq -r '.user_pin')
    local pkcs11_lib=$(echo "$config" | jq -r '.pkcs11_library')
    
    export SOFTHSM2_CONF="$HSM_CONFIG_DIR/softhsm2.conf"
    
    # Test signing
    echo "test data" > "$HSM_CONFIG_DIR/test_data.txt"
    
    pkcs11-tool --module "$pkcs11_lib" --login --pin "$user_pin" \
        --sign --mechanism RSA-PKCS --id 01 \
        --input-file "$HSM_CONFIG_DIR/test_data.txt" \
        --output-file "$HSM_CONFIG_DIR/test_signature.bin"
    
    if [[ -f "$HSM_CONFIG_DIR/test_signature.bin" ]]; then
        success "HSM signing test passed"
    else
        error "HSM signing test failed"
    fi
    
    # Cleanup test files
    rm -f "$HSM_CONFIG_DIR/test_data.txt" "$HSM_CONFIG_DIR/test_signature.bin"
}

# Test TPM functionality
test_tpm() {
    log "Testing TPM functionality..."
    
    if [[ ! -f "$TPM_CONFIG_DIR/tpm_config.json" ]]; then
        warning "TPM not configured. Skipping TPM test."
        return
    fi
    
    # Test signing
    echo "test data" > "$TPM_CONFIG_DIR/test_data.txt"
    
    tpm2_sign -c 0x81000001 -g sha256 -o "$TPM_CONFIG_DIR/test_signature.bin" "$TPM_CONFIG_DIR/test_data.txt"
    
    if [[ -f "$TPM_CONFIG_DIR/test_signature.bin" ]]; then
        success "TPM signing test passed"
    else
        error "TPM signing test failed"
    fi
    
    # Cleanup test files
    rm -f "$TPM_CONFIG_DIR/test_data.txt" "$TPM_CONFIG_DIR/test_signature.bin"
}

# Generate ECPS configuration
generate_ecps_config() {
    log "Generating ECPS configuration..."
    
    local config_file="$ECPS_HOME/hardware_security_config.json"
    
    cat > "$config_file" << EOF
{
    "hardware_security": {
        "enabled": true,
        "hsm": {
            "enabled": $([ -f "$HSM_CONFIG_DIR/softhsm_config.json" ] && echo "true" || echo "false"),
            "config_path": "$HSM_CONFIG_DIR/softhsm_config.json",
            "signing_key_id": "01",
            "encryption_key_id": "02"
        },
        "tpm": {
            "enabled": $([ -f "$TPM_CONFIG_DIR/tpm_config.json" ] && echo "true" || echo "false"),
            "config_path": "$TPM_CONFIG_DIR/tpm_config.json",
            "signing_handle": "0x81000001",
            "encryption_handle": "0x81000002"
        },
        "enrollment_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "enrollment_script_version": "1.0"
    }
}
EOF
    
    chmod 600 "$config_file"
    success "ECPS configuration generated: $config_file"
}

# Print usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS] COMMAND

ECPS HSM/TPM Enrollment Script

COMMANDS:
    detect          Detect available HSM and TPM devices
    setup-softhsm   Setup SoftHSM for testing
    setup-tpm       Setup TPM
    generate-keys   Generate key pairs in HSM/TPM
    test           Test HSM/TPM functionality
    full-setup     Run complete setup process
    config         Generate ECPS configuration

OPTIONS:
    -h, --help      Show this help message
    -v, --verbose   Enable verbose output
    --clear-tpm     Clear TPM before setup (DANGEROUS)

EXAMPLES:
    $0 detect                    # Detect available devices
    $0 setup-softhsm            # Setup SoftHSM for testing
    $0 full-setup               # Complete setup process
    $0 test                     # Test functionality

EOF
}

# Main function
main() {
    local command=""
    local verbose=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            --clear-tpm)
                export CLEAR_TPM=true
                shift
                ;;
            detect|setup-softhsm|setup-tpm|generate-keys|test|full-setup|config)
                command="$1"
                shift
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
    done
    
    if [[ -z "$command" ]]; then
        usage
        exit 1
    fi
    
    # Setup logging
    mkdir -p "$ECPS_HOME"
    log "Starting ECPS HSM/TPM enrollment: $command"
    
    check_root
    setup_directories
    check_dependencies
    
    case "$command" in
        detect)
            detect_hsm
            detect_tpm
            ;;
        setup-softhsm)
            setup_softhsm
            generate_hsm_keypair
            ;;
        setup-tpm)
            setup_tpm
            ;;
        generate-keys)
            generate_hsm_keypair
            ;;
        test)
            test_hsm
            test_tpm
            ;;
        full-setup)
            detect_hsm
            detect_tpm
            setup_softhsm
            generate_hsm_keypair
            setup_tpm
            test_hsm
            test_tpm
            generate_ecps_config
            ;;
        config)
            generate_ecps_config
            ;;
    esac
    
    success "Command completed: $command"
}

# Run main function
main "$@"
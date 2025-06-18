package tests

import (
	"crypto/rand"
	"testing"

	"github.com/ecps/ecps-go/pkg/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHardwareSecurity(t *testing.T) {
	t.Run("HardwareSecurityManager", func(t *testing.T) {
		manager := trust.NewHardwareSecurityManager()
		require.NotNil(t, manager)

		err := manager.Initialize()
		require.NoError(t, err)
		defer manager.Cleanup()

		activeProvider := manager.GetActiveProvider()
		require.NotNil(t, activeProvider)

		availableProviders := manager.GetAvailableProviders()
		assert.Greater(t, len(availableProviders), 0)

		// At least software fallback should be available
		found := false
		for _, provider := range availableProviders {
			if provider.GetHardwareType() == trust.HardwareSecuritySoftwareFallback {
				found = true
				break
			}
		}
		assert.True(t, found, "Software fallback provider should always be available")
	})

	t.Run("SoftwareFallbackProvider", func(t *testing.T) {
		provider := trust.NewSoftwareFallbackProvider()
		require.NotNil(t, provider)

		assert.Equal(t, trust.HardwareSecuritySoftwareFallback, provider.GetHardwareType())
		assert.True(t, provider.IsAvailable())

		err := provider.Initialize()
		require.NoError(t, err)
		defer provider.Cleanup()

		// Test key generation
		identity, err := provider.GenerateKey("test_key")
		require.NoError(t, err)
		assert.NotEmpty(t, identity.DeviceID)
		assert.Equal(t, trust.HardwareSecuritySoftwareFallback, identity.HardwareType)
		assert.Greater(t, len(identity.PublicKey), 0)
		assert.NotNil(t, identity.PlatformInfo)
		assert.NotNil(t, identity.AttestationData)

		// Test signing and verification
		testData := []byte("test data for signing")
		signature, err := provider.Sign("test_key", testData)
		require.NoError(t, err)
		assert.Greater(t, len(signature), 0)

		err = provider.Verify("test_key", testData, signature)
		assert.NoError(t, err)

		// Test verification with wrong data
		wrongData := []byte("wrong data")
		err = provider.Verify("test_key", wrongData, signature)
		assert.Error(t, err)

		// Test device identity
		deviceIdentity, err := provider.GetDeviceIdentity()
		require.NoError(t, err)
		assert.NotEmpty(t, deviceIdentity.DeviceID)
		assert.Equal(t, trust.HardwareSecuritySoftwareFallback, deviceIdentity.HardwareType)
	})

	t.Run("TPMProvider", func(t *testing.T) {
		provider := trust.NewTPMProvider()
		require.NotNil(t, provider)

		assert.Equal(t, trust.HardwareSecurityTPM20, provider.GetHardwareType())

		// TPM may or may not be available depending on the system
		if !provider.IsAvailable() {
			t.Skip("TPM not available on this system")
		}

		err := provider.Initialize()
		if err != nil {
			t.Skip("TPM initialization failed, likely not available")
		}
		defer provider.Cleanup()

		// Test key generation
		identity, err := provider.GenerateKey("tpm_test_key")
		require.NoError(t, err)
		assert.NotEmpty(t, identity.DeviceID)
		assert.Equal(t, trust.HardwareSecurityTPM20, identity.HardwareType)
		assert.Greater(t, len(identity.PublicKey), 0)

		// Test signing and verification
		testData := []byte("tpm test data")
		signature, err := provider.Sign("tpm_test_key", testData)
		require.NoError(t, err)
		assert.Greater(t, len(signature), 0)

		err = provider.Verify("tpm_test_key", testData, signature)
		assert.NoError(t, err)
	})

	t.Run("HardwareIdentity", func(t *testing.T) {
		provider := trust.NewSoftwareFallbackProvider()
		require.NoError(t, provider.Initialize())
		defer provider.Cleanup()

		identity, err := provider.GenerateKey("identity_test")
		require.NoError(t, err)

		// Test ToDict conversion
		identityDict := identity.ToDict()
		assert.Equal(t, identity.DeviceID, identityDict["device_id"])
		assert.Equal(t, string(identity.HardwareType), identityDict["hardware_type"])
		assert.NotEmpty(t, identityDict["public_key"])
		assert.Equal(t, identity.PlatformInfo, identityDict["platform_info"])

		if identity.AttestationData != nil {
			assert.Equal(t, identity.AttestationData, identityDict["attestation_data"])
		}
	})

	t.Run("AttestationReport", func(t *testing.T) {
		provider := trust.NewSoftwareFallbackProvider()
		require.NoError(t, provider.Initialize())
		defer provider.Cleanup()

		// Generate nonce
		nonce := make([]byte, 32)
		_, err := rand.Read(nonce)
		require.NoError(t, err)

		// Create attestation
		report, err := provider.CreateAttestation(nonce, trust.AttestationDeviceIdentity)
		require.NoError(t, err)

		assert.Equal(t, trust.AttestationDeviceIdentity, report.AttestationType)
		assert.NotEmpty(t, report.DeviceID)
		assert.Greater(t, report.Timestamp, float64(0))
		assert.Equal(t, nonce, report.Nonce)
		assert.Greater(t, len(report.Measurements), 0)
		assert.Greater(t, len(report.Signature), 0)

		// Test ToDict conversion
		reportDict := report.ToDict()
		assert.Equal(t, string(report.AttestationType), reportDict["attestation_type"])
		assert.Equal(t, report.DeviceID, reportDict["device_id"])
		assert.Equal(t, report.Timestamp, reportDict["timestamp"])
		assert.NotEmpty(t, reportDict["nonce"])
		assert.Equal(t, report.Measurements, reportDict["measurements"])
		assert.NotEmpty(t, reportDict["signature"])

		// Verify attestation
		err = provider.VerifyAttestation(report)
		assert.NoError(t, err)
	})

	t.Run("AttestationTypes", func(t *testing.T) {
		provider := trust.NewSoftwareFallbackProvider()
		require.NoError(t, provider.Initialize())
		defer provider.Cleanup()

		attestationTypes := []trust.AttestationType{
			trust.AttestationTPMQuote,
			trust.AttestationPlatformAttestation,
			trust.AttestationDeviceIdentity,
			trust.AttestationSecureBoot,
			trust.AttestationRuntimeIntegrity,
		}

		nonce := make([]byte, 32)
		_, err := rand.Read(nonce)
		require.NoError(t, err)

		for _, attestationType := range attestationTypes {
			t.Run(string(attestationType), func(t *testing.T) {
				report, err := provider.CreateAttestation(nonce, attestationType)
				require.NoError(t, err)
				assert.Equal(t, attestationType, report.AttestationType)

				err = provider.VerifyAttestation(report)
				assert.NoError(t, err)
			})
		}
	})

	t.Run("MultipleKeys", func(t *testing.T) {
		provider := trust.NewSoftwareFallbackProvider()
		require.NoError(t, provider.Initialize())
		defer provider.Cleanup()

		keyIDs := []string{"key1", "key2", "key3"}
		identities := make(map[string]*trust.HardwareIdentity)

		// Generate multiple keys
		for _, keyID := range keyIDs {
			identity, err := provider.GenerateKey(keyID)
			require.NoError(t, err)
			identities[keyID] = identity
		}

		// Ensure all keys are different
		for i, keyID1 := range keyIDs {
			for j, keyID2 := range keyIDs {
				if i != j {
					assert.NotEqual(t, identities[keyID1].DeviceID, identities[keyID2].DeviceID)
				}
			}
		}

		// Test signing with different keys
		testData := []byte("multi-key test data")
		for _, keyID := range keyIDs {
			signature, err := provider.Sign(keyID, testData)
			require.NoError(t, err)

			err = provider.Verify(keyID, testData, signature)
			assert.NoError(t, err)

			// Verify that signatures from different keys are different
			for _, otherKeyID := range keyIDs {
				if keyID != otherKeyID {
					err = provider.Verify(otherKeyID, testData, signature)
					assert.Error(t, err, "Signature from %s should not verify with key %s", keyID, otherKeyID)
				}
			}
		}
	})

	t.Run("ErrorHandling", func(t *testing.T) {
		provider := trust.NewSoftwareFallbackProvider()
		require.NoError(t, provider.Initialize())
		defer provider.Cleanup()

		// Test signing with non-existent key
		_, err := provider.Sign("non_existent_key", []byte("test"))
		assert.Error(t, err)

		// Test verification with non-existent key
		err = provider.Verify("non_existent_key", []byte("test"), []byte("signature"))
		assert.Error(t, err)

		// Test verification with invalid signature
		_, err = provider.GenerateKey("test_key")
		require.NoError(t, err)

		err = provider.Verify("test_key", []byte("test"), []byte("invalid_signature"))
		assert.Error(t, err)
	})
}

func TestHardwareSecurityIntegration(t *testing.T) {
	t.Run("ManagerWithMultipleProviders", func(t *testing.T) {
		manager := trust.NewHardwareSecurityManager()
		require.NoError(t, manager.Initialize())
		defer manager.Cleanup()

		activeProvider := manager.GetActiveProvider()
		require.NotNil(t, activeProvider)

		// Test that we can use the active provider
		identity, err := activeProvider.GenerateKey("integration_test")
		require.NoError(t, err)
		assert.NotEmpty(t, identity.DeviceID)

		testData := []byte("integration test data")
		signature, err := activeProvider.Sign("integration_test", testData)
		require.NoError(t, err)

		err = activeProvider.Verify("integration_test", testData, signature)
		assert.NoError(t, err)

		// Create and verify attestation
		nonce := make([]byte, 32)
		_, err = rand.Read(nonce)
		require.NoError(t, err)

		report, err := activeProvider.CreateAttestation(nonce, trust.AttestationDeviceIdentity)
		require.NoError(t, err)

		err = activeProvider.VerifyAttestation(report)
		assert.NoError(t, err)
	})
}
package azidentityext

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// DefaultAzureCredentialOptions contains optional parameters for DefaultAzureCredential.
// These options may not apply to all credentials in the chain.
type DefaultAzureCredentialOptions struct {
	azcore.ClientOptions

	// Toggles to disabling the specified auth method
	DisableEnvironmentCred      bool
	DisableWorkloadIdentityCred bool
	DisableManagedIdentityCred  bool
	DisableAzureCLICred         bool

	// DisableInstanceDiscovery should be true for applications authenticating in disconnected or private clouds.
	// This skips a metadata request that will fail for such applications.
	DisableInstanceDiscovery bool
	// TenantID identifies the tenant the Azure CLI should authenticate in.
	// Defaults to the CLI's default tenant, which is typically the home tenant of the user logged in to the CLI.
	TenantID string
}

// DefaultAzureCredential is a default credential chain for applications that will deploy to Azure.
// It combines credentials suitable for deployment with credentials suitable for local development.
// It attempts to authenticate with each of these credential types, in the following order, stopping
// when one provides a token:
//
//   - [EnvironmentCredential]
//   - [WorkloadIdentityCredential], if environment variable configuration is set by the Azure workload
//     identity webhook. Use [WorkloadIdentityCredential] directly when not using the webhook or needing
//     more control over its configuration.
//   - [ManagedIdentityCredential]
//   - [AzureCLICredential]
//
// Consult the documentation for these credential types for more information on how they authenticate.
// Once a credential has successfully authenticated, DefaultAzureCredential will use that credential for
// every subsequent authentication.
type DefaultAzureCredential struct {
	chain *azidentity.ChainedTokenCredential
}

// NewDefaultAzureCredential creates a DefaultAzureCredential. Pass nil for options to accept defaults.
func NewDefaultAzureCredential(options *DefaultAzureCredentialOptions) (cred *DefaultAzureCredential, credErrors []error, err error) {
	var creds []azcore.TokenCredential

	if options == nil {
		options = &DefaultAzureCredentialOptions{}
	}

	var additionalTenants []string
	if v, ok := os.LookupEnv("AZURE_ADDITIONALLY_ALLOWED_TENANTS"); ok {
		additionalTenants = strings.Split(v, ";")
	}

	envCred, err := azidentity.NewEnvironmentCredential(&azidentity.EnvironmentCredentialOptions{
		ClientOptions: options.ClientOptions, DisableInstanceDiscovery: options.DisableInstanceDiscovery},
	)
	if err == nil {
		creds = append(creds, envCred)
	} else {
		credErrors = append(credErrors, fmt.Errorf("EnvironmentCredential: %v", err))
	}

	// workload identity requires values for AZURE_AUTHORITY_HOST, AZURE_CLIENT_ID, AZURE_FEDERATED_TOKEN_FILE, AZURE_TENANT_ID
	wic, err := azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{
		AdditionallyAllowedTenants: additionalTenants,
		ClientOptions:              options.ClientOptions,
		DisableInstanceDiscovery:   options.DisableInstanceDiscovery,
	})
	if err == nil {
		creds = append(creds, wic)
	} else {
		credErrors = append(credErrors, fmt.Errorf("NetworkloadIdentityCredential: %v", err))
	}
	o := &azidentity.ManagedIdentityCredentialOptions{ClientOptions: options.ClientOptions}
	if ID, ok := os.LookupEnv("AZURE_CLIENT_ID"); ok {
		o.ID = azidentity.ClientID(ID)
	}
	miCred, err := azidentity.NewManagedIdentityCredential(o)
	if err == nil {
		creds = append(creds, miCred)
	} else {
		credErrors = append(credErrors, fmt.Errorf("ManagedIdentityCredential: %v", err))
	}

	cliCred, err := azidentity.NewAzureCLICredential(&azidentity.AzureCLICredentialOptions{AdditionallyAllowedTenants: additionalTenants, TenantID: options.TenantID})
	if err == nil {
		creds = append(creds, cliCred)
	} else {
		credErrors = append(credErrors, fmt.Errorf("AzureCLICredential: %v", err))
	}

	if len(creds) == 0 {
		return nil, credErrors, fmt.Errorf("no credential successfully created")
	}

	chain, err := azidentity.NewChainedTokenCredential(creds, nil)
	if err != nil {
		return nil, credErrors, err
	}
	return &DefaultAzureCredential{chain: chain}, credErrors, nil
}

// GetToken requests an access token from Azure Active Directory. This method is called automatically by Azure SDK clients.
func (c *DefaultAzureCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return c.chain.GetToken(ctx, opts)
}

var _ azcore.TokenCredential = (*DefaultAzureCredential)(nil)

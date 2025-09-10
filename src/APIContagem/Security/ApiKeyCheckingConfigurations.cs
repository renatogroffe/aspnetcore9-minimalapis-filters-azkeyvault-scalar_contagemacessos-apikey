using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

namespace APIContagem.Security;

public class ApiKeyCheckingConfigurations
{
    public string? HeaderName { get; set; }
    public string? ApiKey { get; set; }

    private ApiKeyCheckingConfigurations() { }

    public static async Task<ApiKeyCheckingConfigurations> Initialize(IConfiguration configuration)
    {
        var clientSecretCredential = new ClientSecretCredential(
            tenantId: configuration["AzureSecurity:TenantId"],
            clientId: configuration["AzureSecurity:ClientId"],
            clientSecret: configuration["AzureSecurity:ClientSecret"]);
        var secretClient = new SecretClient(new Uri(configuration["AzureKeyVaultURI"]!),
            clientSecretCredential);
        var secret = await secretClient.GetSecretAsync("apikeyvaluetestes");
        return new ApiKeyCheckingConfigurations()
        {
            HeaderName = configuration["ApiKeyChecking:Header"],
            ApiKey = secret.Value.Value
        };
    }
}
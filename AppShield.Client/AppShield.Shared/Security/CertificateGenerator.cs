using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AppShield.Shared.Security;

public static class CertificateGenerator
{
    private const string CertPassword = "AppShieldLocalTlsCertKey";

    /// <summary>
    /// Loads an existing X.509 certificate from the specified path or creates and saves a new self-signed certificate.
    /// </summary>
    public static X509Certificate2 GetOrCreateCertificate(string certFilePath)
    {
        if (File.Exists(certFilePath))
        {
            try
            {
                return new X509Certificate2(certFilePath, CertPassword, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            }
            catch
            {
                // If corrupted, recreate
            }
        }

        string? dir = Path.GetDirectoryName(certFilePath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            $"CN=AppShieldService, O=AppShield, OU=Security",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));

        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                false));

        req.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.1") }, // Server Authentication
                false));

        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("localhost");
        sanBuilder.AddDnsName(Environment.MachineName);
        sanBuilder.AddIpAddress(IPAddress.Loopback);
        sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);

        req.CertificateExtensions.Add(sanBuilder.Build());

        DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
        DateTimeOffset notAfter = DateTimeOffset.UtcNow.AddYears(5);

        using var cert = req.CreateSelfSigned(notBefore, notAfter);
        byte[] pfxBytes = cert.Export(X509ContentType.Pfx, CertPassword);

        File.WriteAllBytes(certFilePath, pfxBytes);

        return new X509Certificate2(pfxBytes, CertPassword, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
    }
}

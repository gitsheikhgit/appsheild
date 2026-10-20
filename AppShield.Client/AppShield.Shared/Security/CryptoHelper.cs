using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace AppShield.Shared.Security;

public static class CryptoHelper
{
    private const int SaltSize = 16; // 128 bit
    private const int KeySize = 32;  // 256 bit
    private const int Iterations = 100_000;
    private static readonly HashAlgorithmName HashAlgorithm = HashAlgorithmName.SHA256;

    // Cache structure: FilePath -> (LastWriteUtc, Sha256Hash)
    private static readonly ConcurrentDictionary<string, (DateTime LastWriteUtc, string Hash)> HashCache =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Hashes a password using PBKDF2 with SHA-256 and 100,000 iterations.
    /// Format: base64(salt):base64(hash)
    /// </summary>
    public static string HashPassword(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            Iterations,
            HashAlgorithm,
            KeySize);

        return $"{Convert.ToBase64String(salt)}:{Convert.ToBase64String(hash)}";
    }

    /// <summary>
    /// Verifies a password against a stored PBKDF2 hash string in constant time.
    /// </summary>
    public static bool VerifyPassword(string password, string storedHash)
    {
        if (string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(storedHash))
            return false;

        string[] parts = storedHash.Split(':');
        if (parts.Length != 2)
            return false;

        try
        {
            byte[] salt = Convert.FromBase64String(parts[0]);
            byte[] expectedHash = Convert.FromBase64String(parts[1]);

            byte[] actualHash = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                salt,
                Iterations,
                HashAlgorithm,
                expectedHash.Length);

            return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Compares two strings in constant time to prevent timing attacks.
    /// </summary>
    public static bool FixedTimeEquals(string? a, string? b)
    {
        if (a == null || b == null)
            return a == b;

        byte[] aBytes = Encoding.UTF8.GetBytes(a);
        byte[] bBytes = Encoding.UTF8.GetBytes(b);

        return CryptographicOperations.FixedTimeEquals(aBytes, bBytes);
    }

    /// <summary>
    /// Computes the SHA-256 hash of a file with thread-safe caching keyed by FilePath + LastWriteTimeUtc.
    /// Returns lowercase hex string, or empty string if file cannot be read.
    /// </summary>
    public static string ComputeFileSha256(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return string.Empty;

        try
        {
            DateTime lastWriteUtc = File.GetLastWriteTimeUtc(filePath);

            if (HashCache.TryGetValue(filePath, out var cached))
            {
                if (cached.LastWriteUtc == lastWriteUtc && !string.IsNullOrEmpty(cached.Hash))
                {
                    return cached.Hash;
                }
            }

            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var sha256 = SHA256.Create();
            byte[] hashBytes = sha256.ComputeHash(stream);
            string hexHash = Convert.ToHexString(hashBytes).ToLowerInvariant();

            HashCache[filePath] = (lastWriteUtc, hexHash);
            return hexHash;
        }
        catch
        {
            // If the file is locked by the OS or permission is denied, safely return empty
            return string.Empty;
        }
    }
}

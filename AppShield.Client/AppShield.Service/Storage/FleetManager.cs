using System.Text.Json;
using System.Text.Json.Serialization;

namespace AppShield.Service.Storage;

public class FleetNode
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("lan_ip")]
    public string LanIp { get; set; } = string.Empty;

    [JsonPropertyName("tailscale_ip")]
    public string TailscaleIp { get; set; } = string.Empty;

    [JsonPropertyName("port")]
    public int Port { get; set; } = 54120;

    [JsonPropertyName("psk")]
    public string Psk { get; set; } = string.Empty;

    [JsonPropertyName("is_online")]
    public bool IsOnline { get; set; } = false;

    [JsonPropertyName("last_seen_utc")]
    public string LastSeenUtc { get; set; } = string.Empty;

    [JsonPropertyName("os_version")]
    public string OsVersion { get; set; } = string.Empty;

    [JsonPropertyName("client_version")]
    public string ClientVersion { get; set; } = string.Empty;
}

public class FleetManager
{
    private readonly StorageManager _storage;
    private readonly string _fleetFile;
    private readonly object _lock = new();

    public FleetManager(StorageManager storage)
    {
        _storage = storage;
        _fleetFile = Path.Combine(_storage.BaseDirectory, "fleet.json");
    }

    public List<FleetNode> GetAll()
    {
        lock (_lock)
        {
            var nodes = LoadFromFile();
            EnsureLocalNode(nodes);
            return nodes;
        }
    }

    public FleetNode? Get(string id)
    {
        lock (_lock)
        {
            var nodes = GetAll();
            return nodes.FirstOrDefault(n => n.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
        }
    }

    public FleetNode Add(FleetNode node)
    {
        lock (_lock)
        {
            var nodes = GetAll();
            if (string.IsNullOrWhiteSpace(node.Id))
            {
                node.Id = Guid.NewGuid().ToString("N")[..8];
            }
            nodes.Add(node);
            SaveToFile(nodes);
            return node;
        }
    }

    public FleetNode? Update(string id, Dictionary<string, object> updates)
    {
        lock (_lock)
        {
            var nodes = GetAll();
            var target = nodes.FirstOrDefault(n => n.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
            if (target == null) return null;

            foreach (var kvp in updates)
            {
                string key = kvp.Key.ToLowerInvariant();
                string val = kvp.Value?.ToString() ?? string.Empty;

                switch (key)
                {
                    case "name": target.Name = val; break;
                    case "lan_ip": target.LanIp = val; break;
                    case "tailscale_ip": target.TailscaleIp = val; break;
                    case "port": if (int.TryParse(val, out int p)) target.Port = p; break;
                    case "psk": target.Psk = val; break;
                }
            }

            SaveToFile(nodes);
            return target;
        }
    }

    public bool Delete(string id)
    {
        if (id.Equals("local", StringComparison.OrdinalIgnoreCase))
            return false; // Cannot delete local PC

        lock (_lock)
        {
            var nodes = GetAll();
            int removed = nodes.RemoveAll(n => n.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
            if (removed > 0)
            {
                SaveToFile(nodes);
                return true;
            }
            return false;
        }
    }

    private void EnsureLocalNode(List<FleetNode> nodes)
    {
        var local = nodes.FirstOrDefault(n => n.Id.Equals("local", StringComparison.OrdinalIgnoreCase));
        string psk = _storage.GetSetting("PreSharedKey");

        if (local == null)
        {
            local = new FleetNode
            {
                Id = "local",
                Name = $"This PC ({Environment.MachineName})",
                LanIp = "127.0.0.1",
                TailscaleIp = "",
                Port = 54120,
                Psk = psk,
                IsOnline = true,
                LastSeenUtc = DateTime.UtcNow.ToString("o"),
                OsVersion = Environment.OSVersion.ToString(),
                ClientVersion = typeof(FleetManager).Assembly.GetName().Version?.ToString(3) ?? "1.0.0"
            };
            nodes.Insert(0, local);
            SaveToFile(nodes);
        }
        else
        {
            local.IsOnline = true;
            local.Psk = psk;
            local.LastSeenUtc = DateTime.UtcNow.ToString("o");
        }
    }

    private List<FleetNode> LoadFromFile()
    {
        try
        {
            if (File.Exists(_fleetFile))
            {
                string json = File.ReadAllText(_fleetFile);
                return JsonSerializer.Deserialize<List<FleetNode>>(json) ?? new List<FleetNode>();
            }
        }
        catch
        {
        }
        return new List<FleetNode>();
    }

    private void SaveToFile(List<FleetNode> nodes)
    {
        try
        {
            string json = JsonSerializer.Serialize(nodes, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_fleetFile, json);
        }
        catch
        {
        }
    }
}

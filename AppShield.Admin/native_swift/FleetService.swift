import Foundation

// MARK: - Discovered mDNS Service
struct DiscoveredService: Identifiable, Codable, Hashable {
    var id: String { name }
    var name: String
    var primary_ip: String
    var port: Int
    var all_ips: [String]?
    var properties: [String: String]?
}

// MARK: - API Client / Fleet Service
@MainActor
final class FleetService: ObservableObject {
    static let shared = FleetService()

    var basePort: Int = 8085
    private var session: URLSession

    init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 8.0
        config.timeoutIntervalForResource = 15.0
        self.session = URLSession(configuration: config)
    }

    private var baseURL: URL {
        URL(string: "http://127.0.0.1:\(basePort)")!
    }

    // MARK: - Fleet Management
    func fetchFleet() async throws -> [FleetNode] {
        let url = baseURL.appendingPathComponent("/api/fleet")
        let (data, response) = try await session.data(from: url)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            return []
        }
        let env = try JSONDecoder().decode(ApiResponse<[FleetNode]>.self, from: data)
        return env.data ?? []
    }

    func addNode(name: String, lan_ip: String, port: Int, psk: String, tailscale_ip: String?) async throws -> FleetNode? {
        let url = baseURL.appendingPathComponent("/api/fleet")
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")

        var body: [String: Any] = [
            "id": UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(12).lowercased(),
            "name": name,
            "lan_ip": lan_ip,
            "port": port,
            "psk": psk
        ]
        if let ts = tailscale_ip, !ts.isEmpty {
            body["tailscale_ip"] = ts
        }

        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            return nil
        }
        let env = try JSONDecoder().decode(ApiResponse<FleetNode>.self, from: data)
        return env.data
    }

    func deleteNode(id: String) async throws {
        let url = baseURL.appendingPathComponent("/api/fleet/\(id)")
        var req = URLRequest(url: url)
        req.httpMethod = "DELETE"
        _ = try await session.data(for: req)
    }

    func scanMdns() async throws -> [DiscoveredService] {
        let url = baseURL.appendingPathComponent("/api/mdns/scan")
        let (data, response) = try await session.data(from: url)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            return []
        }
        let env = try JSONDecoder().decode(ApiResponse<[DiscoveredService]>.self, from: data)
        return env.data ?? []
    }

    // MARK: - Node Proxy Operations
    func fetchProcesses(nodeId: String) async throws -> [ProcessItem] {
        let url = baseURL.appendingPathComponent("/api/nodes/\(nodeId)/processes")
        let (data, _) = try await session.data(from: url)
        let env = try JSONDecoder().decode(ApiResponse<[ProcessItem]>.self, from: data)
        return env.data ?? []
    }

    func killProcess(nodeId: String, pid: Int) async throws -> Bool {
        let url = baseURL.appendingPathComponent("/api/nodes/\(nodeId)/kill_process")
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: ["pid": pid])
        let (data, _) = try await session.data(for: req)
        let env = try JSONDecoder().decode(ApiResponse<[String: String]>.self, from: data)
        return env.success
    }

    func fetchUsers(nodeId: String) async throws -> [UserAccountItem] {
        let url = baseURL.appendingPathComponent("/api/nodes/\(nodeId)/users")
        let (data, _) = try await session.data(from: url)
        let env = try JSONDecoder().decode(ApiResponse<[UserAccountItem]>.self, from: data)
        return env.data ?? []
    }

    func updateUserJail(nodeId: String, user: UserAccountItem) async throws -> Bool {
        let url = baseURL.appendingPathComponent("/api/nodes/\(nodeId)/users/update")
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body: [String: Any] = [
            "sid": user.sid,
            "username": user.username,
            "isManaged": user.isManaged,
            "blockDownloads": user.blockDownloads ?? false,
            "blockTemp": user.blockTemp ?? false,
            "blockDesktop": user.blockDesktop ?? false,
            "blockUsbDrives": user.blockUsbDrives ?? false
        ]
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, _) = try await session.data(for: req)
        let env = try JSONDecoder().decode(ApiResponse<[String: String]>.self, from: data)
        return env.success
    }

    func fetchRules(nodeId: String) async throws -> [RuleItem] {
        let url = baseURL.appendingPathComponent("/api/nodes/\(nodeId)/rules")
        let (data, _) = try await session.data(from: url)
        let env = try JSONDecoder().decode(ApiResponse<[RuleItem]>.self, from: data)
        return env.data ?? []
    }

    func addRule(nodeId: String, rule: RuleItem) async throws -> Bool {
        let url = baseURL.appendingPathComponent("/api/nodes/\(nodeId)/rules/add")
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        var body: [String: Any] = [
            "ruleType": rule.ruleType,
            "isEnabled": rule.isEnabled
        ]
        if let p = rule.targetPath { body["targetPath"] = p }
        if let pn = rule.targetProcessName { body["targetProcessName"] = pn }
        if let s = rule.scheduleStart { body["scheduleStart"] = s }
        if let e = rule.scheduleEnd { body["scheduleEnd"] = e }
        if let q = rule.dailyQuotaMinutes { body["dailyQuotaMinutes"] = q }
        if let sid = rule.targetUserSid { body["targetUserSid"] = sid }

        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, _) = try await session.data(for: req)
        let env = try JSONDecoder().decode(ApiResponse<[String: String]>.self, from: data)
        return env.success
    }

    func deleteRule(nodeId: String, ruleId: String) async throws -> Bool {
        let url = baseURL.appendingPathComponent("/api/nodes/\(nodeId)/rules/\(ruleId)")
        var req = URLRequest(url: url)
        req.httpMethod = "DELETE"
        let (data, _) = try await session.data(for: req)
        let env = try JSONDecoder().decode(ApiResponse<[String: String]>.self, from: data)
        return env.success
    }

    func fetchInstalledApps(nodeId: String) async throws -> [InstalledAppItem] {
        let url = baseURL.appendingPathComponent("/api/nodes/\(nodeId)/installed_apps")
        let (data, _) = try await session.data(from: url)
        let env = try JSONDecoder().decode(ApiResponse<[InstalledAppItem]>.self, from: data)
        return env.data ?? []
    }

    func fetchLogs(nodeId: String) async throws -> [AuditLogItem] {
        let url = baseURL.appendingPathComponent("/api/nodes/\(nodeId)/logs")
        let (data, _) = try await session.data(from: url)
        let env = try JSONDecoder().decode(ApiResponse<[AuditLogItem]>.self, from: data)
        return env.data ?? []
    }

    func createStandardChildUser(nodeId: String, username: String) async throws -> Bool {
        let url = baseURL.appendingPathComponent("/api/nodes/\(nodeId)/create_child_user")
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: ["username": username])
        let (data, _) = try await session.data(for: req)
        let env = try JSONDecoder().decode(ApiResponse<[String: String]>.self, from: data)
        return env.success
    }
}

import Foundation

// MARK: - Navigation Tabs
enum NavigationTab: String, CaseIterable, Identifiable {
    case overview = "Overview & Fleet"
    case processes = "Live Processes"
    case users = "Users & Child Jail"
    case rules = "Rules & Schedules"
    case installed = "Installed Software"
    case logs = "Audit & Block Logs"
    case settings = "Settings & Uninstaller"

    var id: String { rawValue }

    var iconName: String {
        switch self {
        case .overview: return "shield.lefthalf.filled"
        case .processes: return "waveform.path.ecg"
        case .users: return "person.2.badge.gearshape"
        case .rules: return "clock.badge.checkmark"
        case .installed: return "shippingbox.fill"
        case .logs: return "doc.text.magnifyingglass"
        case .settings: return "gearshape.2.fill"
        }
    }
}

// MARK: - Fleet Node (Computer / Client)
struct FleetNode: Identifiable, Codable, Hashable {
    var id: String
    var name: String
    var lan_ip: String
    var tailscale_ip: String?
    var port: Int
    var psk: String?
    var status: String?
    var active_ip: String?
    var agent_version: String?
    var uptime_seconds: Int?

    var displayName: String {
        return name.isEmpty ? lan_ip : name
    }

    var isOnline: Bool {
        guard let s = status?.lowercased() else { return false }
        return s.hasPrefix("online")
    }

    var effectiveIP: String {
        return active_ip ?? lan_ip
    }
}

// MARK: - Win32 Process Model
struct ProcessItem: Identifiable, Codable, Hashable {
    var id: String { "\(pid)_\(process_name)" }
    var pid: Int
    var process_name: String
    var username: String?
    var user_sid: String?
    var pe_original_filename: String?
    var sha256: String?
    var path: String?
    var ram_mb: Double?

    enum CodingKeys: String, CodingKey {
        case pid
        case process_name
        case username
        case user_sid
        case pe_original_filename
        case sha256
        case path
        case ram_mb
    }
}

// MARK: - Windows User Account Model
struct UserAccountItem: Identifiable, Codable, Hashable {
    var id: String { sid }
    var username: String
    var sid: String
    var isAdmin: Bool
    var isManaged: Bool
    var blockDownloads: Bool?
    var blockTemp: Bool?
    var blockDesktop: Bool?
    var blockUsbDrives: Bool?

    enum CodingKeys: String, CodingKey {
        case username
        case sid
        case isAdmin
        case isManaged
        case blockDownloads
        case blockTemp
        case blockDesktop
        case blockUsbDrives
    }
}

// MARK: - Rule & Schedule Model
struct RuleItem: Identifiable, Codable, Hashable {
    var id: String
    var ruleType: String // BlockPath, AllowedWindow, DailyQuota, KillByName
    var targetPath: String?
    var targetProcessName: String?
    var scheduleStart: String? // "12:00"
    var scheduleEnd: String?   // "20:00"
    var dailyQuotaMinutes: Int?
    var targetUserSid: String?
    var isEnabled: Bool

    enum CodingKeys: String, CodingKey {
        case id
        case ruleType
        case targetPath
        case targetProcessName
        case scheduleStart
        case scheduleEnd
        case dailyQuotaMinutes
        case targetUserSid
        case isEnabled
    }
}

// MARK: - Installed Software Item
struct InstalledAppItem: Identifiable, Codable, Hashable {
    var id: String { (DisplayName ?? "") + (ExeName ?? "") }
    var DisplayName: String?
    var ExeName: String?
    var DisplayVersion: String?
    var Publisher: String?
    var InstallLocation: String?
}

// MARK: - Audit & Block Log Event
struct AuditLogItem: Identifiable, Codable, Hashable {
    var id: String { "\(timestamp)_\(executablePath ?? "")_\(pid ?? 0)" }
    var timestamp: String
    var eventType: String
    var executablePath: String?
    var processName: String?
    var pid: Int?
    var userSid: String?
    var username: String?
    var reason: String?
    var actionTaken: String?
}

// MARK: - Generic API Envelope
struct ApiResponse<T: Codable>: Codable {
    var success: Bool
    var data: T?
    var error: String?
}

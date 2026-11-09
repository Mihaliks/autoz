// AutoZ — выбранный часовой пояс в строке меню и системный пояс по внешнему IP.
// displayZone хранит выбор часов независимо от homeZone и системной синхронизации.
// Заголовок, подсказка, статусная таблица и разница во времени используют displayTimeZone().
// Формат заголовка следует системному формату; оранжевый цвет означает отличие от системного времени.
//
// 改时区（关键约束）：
//   macOS 不存在「当前进程直接变 root」的 API —— 这是刻意的安全边界。能改系统时区的只有 root
//   进程改 /etc/localtime（systemsetup 也是干这个）。所以能优化的只是「怎么拿到 root」，三条通道：
//
//     通道 0（默认）· 免授权助手：/Library/LaunchDaemons 下的 launchd 任务（root），
//       由 Sockets 键按需拉起、空闲 20s 自动退出（**不常驻**）。装一次（输一次密码）之后，
//       改时区走本地 Unix socket，**零弹窗**，重启也有效。接口极窄：只认 set_zone/set_auto/ping，
//       校验对端 uid + 时区白名单，见 Sources/helper.swift。
//
//     通道 1 · 原生一次性授权：Security.framework 的 AuthorizationCreate 弹系统认证框，
//       再经 authshim.c 转调 AuthorizationExecuteWithPrivileges，以 argv 数组直接执行系统二进制
//       （/usr/bin/defaults、/usr/sbin/systemsetup、/bin/ln），**全程不经过 shell**。
//
//     通道 2 · AppleScript 一次性授权：osascript `do shell script ... with administrator privileges`。
//
//   通道 1/2 **每次都会弹一次系统认证窗口**。这一点是实测结论，不是保守估计：
//   日志里 09:45:56 授权成功后，09:49:24 同一次运行内又弹了一次（原生返回 -60006 = 已取消）。
//   macOS 的授权凭证不跨调用复用，所以「一次授权、永久生效」只能靠通道 0。

import Cocoa
import Security
import Network

// 由 authshim.c 提供：转调 AuthorizationExecuteWithPrivileges（Swift 无法直接导入该符号）
@_silgen_name("AutoZExecWithPrivileges")
func tzExecPriv(_ auth: UnsafeMutableRawPointer,
                _ tool: UnsafePointer<CChar>,
                _ argv: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> Int32

// MARK: - 常量

enum K {
    static let beijingID   = "Asia/Shanghai"
    static let zoneRoot    = "/var/db/timezone/zoneinfo/"
    static let autoTZPlist = "/Library/Preferences/com.apple.timezone.auto"
    /// 版本号以 Info.plist 为准（构建时由 build.sh 的 AUTOZ_VERSION 注入并写入 plist）；
    /// 直接跑裸二进制时回退到编译期默认值。
    static let version: String = {
        if let v = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
           !v.isEmpty { return v }
        return "0.9.0-ru.2"
    }()
    static let logPath     = NSHomeDirectory() + "/Library/Logs/AutoZ.log"
    static let appSupport  = NSHomeDirectory() + "/Library/Application Support/AutoZ"
}

/// 实际 bundle id（直接运行二进制时为 nil，退化为编译期默认值）
let bundleID = Bundle.main.bundleIdentifier ?? "cn.y10n.autoz"

// MARK: - 对外命名
//
// 改名只动两处：这里（代码侧）与 build.sh 的 AUTOZ_DISPLAY_NAME（Info.plist 侧）。
//
// 注意区分两类名字：
//   · 显示名（appDisplayName）    —— 给人看的，可以随便改
//   · 存储标识（bundleID / "AutoZ" 日志与配置目录）—— 给系统看的，改了会让老用户
//     的日志、偏好设置、Application Support 失联，所以**不跟随显示名变化**。

/// 产品显示名：高级配置窗口、帮助文案统一用它。
/// 与 bundle id 一样以构建期写入的 Info.plist 为准，直接跑裸二进制时回退到默认值。
let appDisplayName: String =
    (Bundle.main.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
        .flatMap { $0.isEmpty ? nil : $0 } ?? "AutoZ — часовые пояса"

/// 一句话定位，避免同一句话散落在多个界面里各自漂移。
let appTagline = "Выбранный часовой пояс в меню · Системный часовой пояс по IP"

/// 菜单栏标题字体。
///
/// 字号取 13pt —— 这就是系统菜单栏时钟的字号（`NSFont.menuBarFont(ofSize: 0).pointSize`
/// 也是 13.0），两者并排渲染出来的宽度对得上（实测系统时钟那串「9月22日 周二 20:30」
/// 占 123px，13pt 渲染为 120.9px，12pt 只有 112.3px）。早先用 12pt，明显小一号。
///
/// 用等宽数字（monospacedDigit）是为了秒数跳动时标题宽度不抖 —— 系统时钟也这么做。
/// 集中在这里定义，避免设置处和每次 tick 渲染处各写一份然后漂移。
let menuBarTitleFont = NSFont.monospacedDigitSystemFont(ofSize: 13, weight: .regular)

// MARK: - 开机自启（用户级 LaunchAgent）

/// 开机自启用登录项实现，但**刻意不用 SMAppService** ——
/// 实测：ad-hoc 签名（无 Team ID）下 `SMAppService.mainApp.register()`
/// 直接 SIGTRAP 把进程干掉，Swift 的 do/catch 根本拦不住。本项目对外发布的
/// 就是 ad-hoc 签名包，所以改用用户级 LaunchAgent：
///
///   · 只写 `~/Library/LaunchAgents/`，**不需要管理员密码**
///   · 同样会出现在「系统设置 → 通用 → 登录项」里，用户可随时撤销
///   · 卸载只需删掉这一个文件，不留残渣
///
/// 若将来用 Developer ID 正式签名并公证，可以再换回 SMAppService。
enum LoginItem {
    /// 用 bundle id 当 launchd label，便于在登录项列表里认出
    static let label = "cn.y10n.autoz"

    static var plistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    /// 写进 plist 的可执行文件路径。用 Bundle.main 推导，
    /// App 放在哪就注册哪，不写死 /Applications。
    static var executablePath: String { Bundle.main.executablePath ?? "" }

    static var isEnabled: Bool {
        FileManager.default.fileExists(atPath: plistURL.path)
    }

    /// App 是否在「应用程序」目录里 —— 不在的话，用户移动或删除它之后自启就会失效，
    /// 所以状态文案要提醒，不能只显示「已启用」。
    static var bundleInApplications: Bool {
        Bundle.main.bundlePath.hasPrefix("/Applications/")
    }

    /// 状态的人话说明，直接显示在界面上
    static var statusText: String {
        guard isEnabled else { return "Выключен" }
        if executablePath.isEmpty || !FileManager.default.fileExists(atPath: executablePath) {
            return "Включён, но путь устарел. Выключите и включите автозапуск снова"
        }
        if !bundleInApplications {
            return "Включён (приложение вне папки «Программы»; после перемещения путь потребуется обновить)"
        }
        return "Включён; запуск при следующем входе в систему"
    }

    /// 开启 / 关闭。成功返回 nil，失败返回原因（供提示与日志使用）。
    /// 写文件是即时的，但 launchd 要**下次登录**才会读取，所以界面文案不要写成「已生效」。
    static func set(_ on: Bool) -> String? {
        let fm = FileManager.default
        guard !executablePath.isEmpty else { return "Не удалось определить путь к исполняемому файлу" }

        if on {
            do {
                try fm.createDirectory(at: plistURL.deletingLastPathComponent(),
                                       withIntermediateDirectories: true)
                try plistXML().write(to: plistURL, atomically: true, encoding: .utf8)
                return nil
            } catch {
                return error.localizedDescription
            }
        } else {
            do {
                if fm.fileExists(atPath: plistURL.path) { try fm.removeItem(at: plistURL) }
                return nil
            } catch {
                return error.localizedDescription
            }
        }
    }

    /// 首次运行默认开启。
    /// 用户的诉求是「避免很多时候搞忘开启了」—— 那就别指望他记得去点，默认就开。
    ///
    /// 用 UserDefaults 记一个「已初始化」标记：用户之后手动关掉，不会被下次启动打回。
    /// 另外只在 App 已经待在「应用程序」目录时才登记 —— 从 build/ 目录直接跑起来时
    /// 若写了 plist，登录项会指向构建目录，既没用又容易留下垃圾。
    static func applyFirstRunDefault() {
        // 不在「应用程序」里就别登记，也**不要**置标记，等用户装好后下次启动再补
        guard bundleInApplications else {
            log("Первый запуск: приложение вне папки «Программы» (\(Bundle.main.bundlePath)); автозапуск не зарегистрирован")
            return
        }
        let key = "autoz.launchAtLogin.initialized"
        let d = UserDefaults.standard
        guard d.object(forKey: key) == nil else { return }   // 已经处理过, 尊重用户的当前选择
        d.set(true, forKey: key)
        guard !isEnabled else { return }
        if let err = set(true) {
            log("Первый запуск: не удалось включить автозапуск — \(err)")
        } else {
            log("Первый запуск: автозапуск включён (отключается в настройках)")
        }
    }

    /// 路径里可能有 & < > 之类字符，写进 XML 前必须转义，否则 plist 会解析失败
    private static func xmlEscape(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;")
         .replacingOccurrences(of: "<", with: "&lt;")
         .replacingOccurrences(of: ">", with: "&gt;")
    }

    private static func plistXML() -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key><string>\(xmlEscape(label))</string>
            <key>ProgramArguments</key>
            <array><string>\(xmlEscape(executablePath))</string></array>
            <key>RunAtLoad</key><true/>
            <key>LimitLoadToSessionType</key><string>Aqua</string>
            <key>ProcessType</key><string>Interactive</string>
        </dict>
        </plist>
        """
    }
}

// MARK: - 日志

private let logQueue = DispatchQueue(label: "autoz.log")

func log(_ msg: String) {
    let line = "[\(stamp(Date()))] \(msg)\n"
    logQueue.async {
        let fm = FileManager.default
        if !fm.fileExists(atPath: K.logPath) {
            fm.createFile(atPath: K.logPath, contents: nil)
        }
        // 超过 512KB 就轮转一次，避免无限增长
        if let attrs = try? fm.attributesOfItem(atPath: K.logPath),
           let size = attrs[.size] as? Int, size > 512 * 1024 {
            try? fm.removeItem(atPath: K.logPath + ".1")
            try? fm.moveItem(atPath: K.logPath, toPath: K.logPath + ".1")
            fm.createFile(atPath: K.logPath, contents: nil)
        }
        if let fh = FileHandle(forWritingAtPath: K.logPath) {
            fh.seekToEndOfFile()
            fh.write(line.data(using: .utf8)!)
            try? fh.close()
        }
    }
}

func stamp(_ d: Date) -> String {
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_US_POSIX")
    f.dateFormat = "yyyy-MM-dd HH:mm:ss"
    return f.string(from: d)
}

// MARK: - 进程执行

@discardableResult
func runProcess(_ path: String, _ args: [String]) -> (status: Int32, out: String, err: String) {
    guard FileManager.default.isExecutableFile(atPath: path) else {
        return (-1, "", "Файл не исполняемый: \(path)")
    }
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let op = Pipe(), ep = Pipe()
    p.standardOutput = op
    p.standardError = ep
    do { try p.run() } catch { return (-1, "", "\(error)") }
    // 输出量极小（远小于管道缓冲），先读完再 wait 不会死锁
    let od = op.fileHandleForReading.readDataToEndOfFile()
    let ed = ep.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return (p.terminationStatus,
            String(decoding: od, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines),
            String(decoding: ed, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
}

func osaQuote(_ s: String) -> String {
    "\"" + s.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"") + "\""
}

// MARK: - 通知
//
// 一律走程序内自绘横幅（ToastCenter，见 ui.swift），不再用 osascript，也不依赖系统通知权限：
//   ・osascript display notification 会以「脚本编辑器」的身份弹出来，观感很差；
//   ・macOS 27 拒绝给 ad-hoc 签名的 App 注册 UNUserNotificationCenter（实测 UNErrorDomain Code=1）。
//   自绘横幅零权限、跟随系统外观、样式与 App 图标统一。

func notify(title: String, message: String, sound: String? = "Glass") {
    ToastCenter.shared.post(title: title, message: message, sound: sound)
}

// MARK: - 网络

private let httpQueue = DispatchQueue(label: "autoz.http")

func httpGetJSON(_ urlString: String, timeout: TimeInterval = 12) throws -> [String: Any] {
    guard let url = URL(string: urlString) else { throw TZError.network("Некорректный URL: \(urlString)") }
    var req = URLRequest(url: url)
    req.timeoutInterval = timeout
    req.cachePolicy = .reloadIgnoringLocalCacheData
    req.setValue("AutoZ/\(K.version) (macOS menu bar utility)", forHTTPHeaderField: "User-Agent")

    var payload: Data?
    var failure: Error?
    let sem = DispatchSemaphore(value: 0)
    let cfg = URLSessionConfiguration.ephemeral
    cfg.waitsForConnectivity = false
    cfg.timeoutIntervalForRequest = timeout
    let session = URLSession(configuration: cfg)
    session.dataTask(with: req) { data, resp, err in
        if let err = err { failure = err }
        else if let http = resp as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            failure = TZError.network("HTTP \(http.statusCode)")
        } else { payload = data }
        sem.signal()
    }.resume()
    if sem.wait(timeout: .now() + timeout + 5) == .timedOut { throw TZError.network("Время ожидания запроса истекло") }
    session.invalidateAndCancel()
    if let e = failure { throw e }
    guard let data = payload, !data.isEmpty else { throw TZError.network("Пустой ответ") }
    guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw TZError.network("Ответ не является объектом JSON")
    }
    return obj
}

enum TZError: LocalizedError {
    case network(String)
    case noTimeZone(String)
    case shell(String)
    case cancelled

    var errorDescription: String? {
        switch self {
        case .network(let s):     return "Ошибка сети: \(s)"
        case .noTimeZone(let s):  return "Не удалось определить часовой пояс: \(s)"
        case .shell(let s):       return "Ошибка выполнения команды: \(s)"
        case .cancelled:          return "Отменено (нет разрешения администратора)"
        }
    }
}

// MARK: - 数据模型

struct Detection: Codable {
    var ip: String
    var city: String
    var region: String
    var country: String
    var org: String
    var source: String        // 数据来源
    var zoneID: String        // 解析出的 IANA 时区
    var zoneSource: String    // 时区是怎么定出来的
    var rawJSON: String
    var fetchedAt: Date

    var locationText: String {
        [city, region, country].filter { !$0.isEmpty }.joined(separator: ", ")
    }
}

// MARK: - 单时区国家回退表（只收录「全国统一一个时区」的国家/地区，避免给出错误答案）

private let singleZoneCountries: [String: String] = [
    "CN": "Asia/Shanghai", "HK": "Asia/Hong_Kong", "MO": "Asia/Macau", "TW": "Asia/Taipei",
    "JP": "Asia/Tokyo", "KR": "Asia/Seoul", "KP": "Asia/Pyongyang", "SG": "Asia/Singapore",
    "MY": "Asia/Kuala_Lumpur", "TH": "Asia/Bangkok", "VN": "Asia/Ho_Chi_Minh", "PH": "Asia/Manila",
    "KH": "Asia/Phnom_Penh", "LA": "Asia/Vientiane", "MM": "Asia/Yangon", "BN": "Asia/Brunei",
    "IN": "Asia/Kolkata", "PK": "Asia/Karachi", "BD": "Asia/Dhaka", "LK": "Asia/Colombo",
    "NP": "Asia/Kathmandu", "AE": "Asia/Dubai", "SA": "Asia/Riyadh", "QA": "Asia/Qatar",
    "KW": "Asia/Kuwait", "BH": "Asia/Bahrain", "OM": "Asia/Muscat", "IR": "Asia/Tehran",
    "IL": "Asia/Jerusalem", "TR": "Europe/Istanbul", "EG": "Africa/Cairo", "ZA": "Africa/Johannesburg",
    "NG": "Africa/Lagos", "KE": "Africa/Nairobi", "ET": "Africa/Addis_Ababa",
    "GB": "Europe/London", "IE": "Europe/Dublin", "FR": "Europe/Paris", "DE": "Europe/Berlin",
    "IT": "Europe/Rome", "NL": "Europe/Amsterdam", "BE": "Europe/Brussels", "CH": "Europe/Zurich",
    "AT": "Europe/Vienna", "SE": "Europe/Stockholm", "NO": "Europe/Oslo", "DK": "Europe/Copenhagen",
    "FI": "Europe/Helsinki", "PL": "Europe/Warsaw", "CZ": "Europe/Prague", "SK": "Europe/Bratislava",
    "HU": "Europe/Budapest", "RO": "Europe/Bucharest", "GR": "Europe/Athens", "BG": "Europe/Sofia",
    "HR": "Europe/Zagreb", "RS": "Europe/Belgrade",
]

let zoneIDPattern = try! NSRegularExpression(pattern: "^[A-Za-z0-9_+./-]{3,64}$")

func isValidZoneID(_ id: String) -> Bool {
    guard TimeZone(identifier: id) != nil else { return false }
    let r = NSRange(id.startIndex..<id.endIndex, in: id)
    return zoneIDPattern.firstMatch(in: id, range: r) != nil
}

// MARK: - 检测器

enum Checker {

    static func run() throws -> Detection {
        var failures: [String] = []
        // 1) ipinfo.io（主源）
        if let det = try? fromIpinfo() { return det }
        else { failures.append("Ошибка ipinfo.io") }
        // 2) ipwho.is（备源）
        if let det = try? fromIpwho() { return det }
        else { failures.append("Ошибка ipwho.is") }
        throw TZError.network(failures.joined(separator: "; "))
    }

    private static func fromIpinfo() throws -> Detection {
        let j = try httpGetJSON("https://ipinfo.io/json")
        return try build(json: j,
                         ip: j["ip"] as? String ?? "",
                         city: j["city"] as? String ?? "",
                         region: j["region"] as? String ?? "",
                         country: j["country"] as? String ?? "",
                         org: j["org"] as? String ?? "",
                         zone: j["timezone"] as? String,
                         source: "ipinfo.io/json")
    }

    private static func fromIpwho() throws -> Detection {
        let j = try httpGetJSON("https://ipwho.is/")
        if let ok = j["success"] as? Bool, ok == false {
            throw TZError.network("ipwho.is вернул ошибку")
        }
        let tz = (j["timezone"] as? [String: Any])?["id"] as? String
        return try build(json: j,
                         ip: j["ip"] as? String ?? "",
                         city: j["city"] as? String ?? "",
                         region: j["region"] as? String ?? "",
                         country: j["country_code"] as? String ?? (j["country"] as? String ?? ""),
                         org: (j["connection"] as? [String: Any])?["isp"] as? String ?? "",
                         zone: tz,
                         source: "ipwho.is")
    }

    private static func build(json: [String: Any], ip: String, city: String, region: String,
                              country: String, org: String, zone: String?, source: String) throws -> Detection {
        var zoneID = ""
        var zoneSource = ""

        if let z = zone, isValidZoneID(z) {
            zoneID = z
            zoneSource = "\(source) · поле timezone"
        } else if let cc = country.isEmpty ? nil : country.uppercased(), let z = singleZoneCountries[cc] {
            zoneID = z
            zoneSource = "Таблица стран с одним часовым поясом (\(cc))"
        }

        guard !zoneID.isEmpty, let tz = TimeZone(identifier: zoneID) else {
            throw TZError.noTimeZone("\(source) не вернул корректный timezone (значение \(zone ?? "nil"))")
        }
        // 用 secOffset 做一次自检，确保可用
        _ = tz.secondsFromGMT(for: Date())

        let raw = (try? JSONSerialization.data(withJSONObject: json, options: [.sortedKeys, .prettyPrinted]))
            .flatMap { String(data: $0, encoding: .utf8) } ?? "{}"

        return Detection(ip: ip, city: city, region: region, country: country, org: org,
                         source: source, zoneID: zoneID, zoneSource: zoneSource,
                         rawJSON: raw, fetchedAt: Date())
    }
}

// MARK: - 系统时区读写

func systemZoneID() -> String {
    func strip(_ link: String) -> String? {
        for root in [K.zoneRoot, "/usr/share/zoneinfo/"] where link.hasPrefix(root) {
            let id = String(link.dropFirst(root.count))
            return id.isEmpty ? nil : id
        }
        return nil
    }
    if let link = try? FileManager.default.destinationOfSymbolicLink(atPath: "/etc/localtime") {
        if let id = strip(link) { return id }
        if link.hasSuffix("/var/db/timezone/localtime") || link == "/var/db/timezone/localtime" {
            if let inner = try? FileManager.default.destinationOfSymbolicLink(atPath: "/var/db/timezone/localtime"),
               let id = strip(inner) { return id }
        }
    }
    // 兜底：进程启动时缓存的时区（可能滞后，仅作最后手段）
    let cached = TimeZone.current.identifier
    return cached == "GMT" ? "" : cached
}

/// 读取 /Library/Preferences/com.apple.timezone.auto 的 Active（无需提权）
func autoTimeZoneEnabled() -> Bool? {
    let r = runProcess("/usr/bin/defaults", ["read", K.autoTZPlist, "Active"])
    if r.status != 0 { return nil }
    let v = r.out.lowercased()
    if v == "1" || v == "true" || v == "yes" { return true }
    if v == "0" || v == "false" || v == "no" { return false }
    return nil
}

enum ApplyOutcome {
    case changed(String)            // 成功改成某时区
    case already(String)            // 本来就是该时区
    case cancelled
    case failed(String)
}

/// 生成「一次性提权」的 AppleScript（回退后端）；autoTZ 非 nil 时顺带写入自动时区开关。
/// 说明：zoneID 已通过 isValidZoneID 白名单校验（仅 [A-Za-z0-9_+./-]），可安全内插。
func buildOsaCommand(zoneID: String, autoTZ: Bool?) -> String {
    var parts: [String] = []
    if let a = autoTZ {
        parts.append("/usr/bin/defaults write \(K.autoTZPlist) Active -bool \(a ? "true" : "false") >/dev/null 2>&1")
    }
    parts.append("/usr/sbin/systemsetup -settimezone \(osaQuote(zoneID)) >/dev/null 2>&1")
    parts.append("if [ \"$(/usr/bin/readlink /etc/localtime)\" != \"\(K.zoneRoot)\(zoneID)\" ]; "
                 + "then /bin/ln -sfn \"\(K.zoneRoot)\(zoneID)\" /etc/localtime; "
                 + "/usr/bin/notifyutil -p com.apple.system.timezone >/dev/null 2>&1; fi")
    parts.append("/usr/bin/readlink /etc/localtime")
    return "do shell script \(osaQuote(parts.joined(separator: "; "))) with administrator privileges"
}

// MARK: - 特权助手通道（免授权）
//
// 背景（实测结论）：Security.framework 与 AppleScript 两条一次性的路**每次调用都要重新授权**，
// 凭证不会跨调用复用。实测日志：09:45 授权成功后，09:49 同一次运行里又弹了一次。
// 要真正做到「装一次、以后都不弹」，唯一正路是装一个现成的特权通道：
//
//   安装（输一次密码）→ /Library/LaunchDaemons 下的 launchd 任务（root）
//   之后改时区 → 本地 Unix socket 通信，**零弹窗**（重启也有效，launchd 会重新加载任务）

enum HelperK {
    static let label      = "cn.y10n.autoz.helper"
    static let socketPath = "/var/run/cn.y10n.autoz.sock"
    static let plistPath  = "/Library/LaunchDaemons/cn.y10n.autoz.helper.plist"
    static let binPath    = "/usr/local/libexec/autoz-helper"
    static let logPath    = "/var/log/cn.y10n.autoz.helper.log"
}

struct HelperReply {
    var ok: Bool
    var msg: String
    var zone: String?
    var auto: Bool?
    var changed: Bool
    var steps: [String]
    var raw: [String: Any]
}

enum HelperChannel {
    static var socketExists: Bool { FileManager.default.fileExists(atPath: HelperK.socketPath) }
    static var plistInstalled: Bool { FileManager.default.fileExists(atPath: HelperK.plistPath) }
    static var binaryInstalled: Bool { FileManager.default.isExecutableFile(atPath: HelperK.binPath) }

    /// 待安装的助手二进制来源：优先 app bundle 内 Resources/autoz-helper，CLI 模式取同级目录
    static var binarySource: String? {
        if let r = Bundle.main.resourcePath {
            let p = r + "/autoz-helper"
            if FileManager.default.isExecutableFile(atPath: p) { return p }
        }
        let exe = Bundle.main.executablePath ?? CommandLine.arguments[0]
        let sib = (exe as NSString).deletingLastPathComponent + "/autoz-helper"
        return FileManager.default.isExecutableFile(atPath: sib) ? sib : nil
    }

    /// 发一条指令并等一行 JSON 回复。socket 不存在/连不上/超时 → nil（调用方据此回退）
    static func request(_ payload: [String: Any], timeout: TimeInterval = 25) -> HelperReply? {
        guard FileManager.default.fileExists(atPath: HelperK.socketPath),
              let body = try? JSONSerialization.data(withJSONObject: payload) else { return nil }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let cap = MemoryLayout.size(ofValue: addr.sun_path)
        withUnsafeMutablePointer(to: &addr.sun_path) { p in
            p.withMemoryRebound(to: CChar.self, capacity: cap) {
                _ = strlcpy($0, HelperK.socketPath, cap)
            }
        }
        let len = socklen_t(MemoryLayout<sa_family_t>.size + HelperK.socketPath.utf8.count + 1)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, len) }
        }
        guard rc == 0 else { return nil }
        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var out = body
        out.append(0x0A)
        out.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var off = 0
            while off < out.count {
                let n = write(fd, base.advanced(by: off), out.count - off)
                if n <= 0 { break }
                off += n
            }
        }
        var buf = Data()
        var chunk = [UInt8](repeating: 0, count: 4096)
        while !buf.contains(0x0A) {
            let n = read(fd, &chunk, chunk.count)
            if n <= 0 { break }
            buf.append(contentsOf: chunk[0..<n])
        }
        guard let nl = buf.firstIndex(of: 0x0A),
              let obj = (try? JSONSerialization.jsonObject(with: buf.subdata(in: buf.startIndex..<nl))) as? [String: Any]
        else { return nil }
        return HelperReply(ok: obj["ok"] as? Bool ?? false,
                           msg: obj["msg"] as? String ?? "",
                           zone: obj["zone"] as? String,
                           auto: obj["auto"] as? Bool,
                           changed: obj["changed"] as? Bool ?? false,
                           steps: obj["steps"] as? [String] ?? [],
                           raw: obj)
    }

    static func ping() -> HelperReply? { request(["cmd": "ping"], timeout: 8) }

    static func setZone(_ zone: String, auto: Bool?) -> HelperReply? {
        var p: [String: Any] = ["cmd": "set_zone", "zone": zone]
        if let a = auto { p["auto"] = a }
        return request(p, timeout: 30)
    }

    /// 人类可读的通道状态（菜单/诊断用）
    static var statusText: String {
        if !socketExists { return plistInstalled ? "Установлен, но сокет не готов" : "Не установлен (для каждой смены пояса нужен пароль)" }
        if let r = ping() {
            let extra = (r.raw["zone"] as? String).map { " · пояс по данным помощника: \($0)" } ?? ""
            return "Готов · Без запроса пароля, в том числе после перезагрузки" + extra
        }
        return socketExists ? "Сокет есть, но помощник не отвечает (переустановите его)" : "Не установлен"
    }
}

// MARK: - 一次性授权：统一「特权命令计划」执行器
//
// 说明：助手通道**只能**改时区（窄接口，见 helper.swift），装/卸助手本身必须走这里的一次性授权 ——
// 这是设计上的取舍：不给助手留下「执行任意计划」的能力，否则它就等于一个 root 后门。

struct PrivStep {
    var tool: String
    var args: [String]
    var note: String?
    var ignoreFailure: Bool

    init(_ tool: String, _ args: [String], note: String? = nil, ignoreFailure: Bool = false) {
        self.tool = tool
        self.args = args
        self.note = note
        self.ignoreFailure = ignoreFailure
    }

    var display: String {
        ([tool] + args.map { $0.contains(" ") ? "\"\($0)\"" : $0 }).joined(separator: " ")
    }
}

struct PrivResult {
    var ok: Bool
    var cancelled: Bool
    var backend: String
    var executed: [(step: String, status: Int32, err: String)]
    var msg: String

    var summary: String {
        let failed = executed.filter { $0.status != 0 && $0.status != -999 }
        if cancelled { return "Авторизация отменена" }
        if ok || failed.isEmpty { return "Выполнены все шаги: \(executed.count)" }
        return "Ошибки на \(failed.count) из \(executed.count) шагов: " + failed.map { "\($0.step) → \($0.status)" }.joined(separator: "; ")
    }
}

/// 用一次授权执行整串特权命令。优先原生 Security.framework，不可用时回退 AppleScript。
func runPrivilegedPlan(_ steps: [PrivStep], reason: String) -> PrivResult {
    if steps.isEmpty {
        return PrivResult(ok: true, cancelled: false, backend: "нет", executed: [], msg: "Ничего выполнять не требуется")
    }
    log("План с правами администратора (\(reason)): \(steps.count) шагов, способ=\(Store.shared.privBackend.rawValue)")
    for s in steps { log("  · \(s.display)\(s.note.map { "   ← \($0)" } ?? "")") }

    var nativeUnusable = false

    // ---- 后端 A：原生 Security.framework（argv 直传，不经 shell）----
    if Store.shared.privBackend != .appleScript {
        var ref: AuthorizationRef?
        let st = AuthorizationCreate(nil, nil, [.interactionAllowed, .extendRights, .preAuthorize], &ref)
        if st == errAuthorizationCanceled {
            return PrivResult(ok: false, cancelled: true, backend: "native", executed: [], msg: "Авторизация отменена")
        }
        if st == errAuthorizationSuccess, let auth = ref {
            defer { AuthorizationFree(auth, []) }
            var executed: [(String, Int32, String)] = []
            var allOK = true
            for s in steps {
                let status = execPrivileged(auth, s.tool, s.args)
                executed.append((s.display, status, ""))
                log("  Security.framework: \(s.display) → \(status)")
                if status == errAuthorizationCanceled {
                    return PrivResult(ok: false, cancelled: true, backend: "native", executed: executed,
                                      msg: "Авторизация отменена")
                }
                if status == -60031 {          // errAuthorizationToolExecuteFailure: 符号失效
                    nativeUnusable = true
                    break
                }
                if status != 0 && !s.ignoreFailure { allOK = false; break }
            }
            if !nativeUnusable {
                Store.shared.lastBackend = "native"
                return PrivResult(ok: allOK, cancelled: false, backend: "native", executed: executed,
                                  msg: allOK ? "Выполнены все шаги: \(executed.count)" : "Не все шаги выполнены")
            }
            log("Security.framework вернул -60031 → переход на AppleScript")
        } else {
            log("Security.framework недоступен: AuthorizationCreate -> \(st) → переход на AppleScript")
        }
    }
    if Store.shared.privBackend == .native && nativeUnusable {
        log("Выбран native, но этот API недоступен на этом Mac")
    }

    // ---- 后端 B：AppleScript 一次性授权 ----
    let cmds = steps.map { ([$0.tool] + $0.args).map(osaQuote).joined(separator: " ") }
    let script = "do shell script \(osaQuote(cmds.joined(separator: "; "))) with administrator privileges"
    log("План AppleScript: \(cmds.count) команд")
    let r = runProcess("/usr/bin/osascript", ["-e", script])
    Store.shared.lastBackend = "appleScript"
    if r.status != 0 {
        if r.err.contains("User canceled") || r.err.contains("-128") || r.err.contains("canceled") {
            return PrivResult(ok: false, cancelled: true, backend: "appleScript", executed: [], msg: "Авторизация отменена")
        }
        return PrivResult(ok: false, cancelled: false, backend: "appleScript", executed: [],
                          msg: r.err.isEmpty ? "osascript status=\(r.status)" : r.err)
    }
    log("Ответ AppleScript: \(r.out)")
    return PrivResult(ok: true, cancelled: false, backend: "appleScript",
                      executed: cmds.map { ($0, 0, "") }, msg: "Выполнены все шаги: \(cmds.count)")
}

// MARK: - 助手的安装 / 卸载（走一次性授权）

enum HelperInstaller {

    static func plistXML(allowUID: uid_t) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(HelperK.label)</string>
            <key>Sockets</key>
            <dict>
                <key>Listeners</key>
                <dict>
                    <key>SockPathName</key>
                    <string>\(HelperK.socketPath)</string>
                    <key>SockPathMode</key>
                    <integer>438</integer>
                    <key>SockType</key>
                    <string>stream</string>
                </dict>
            </dict>
            <key>ProgramArguments</key>
            <array>
                <string>\(HelperK.binPath)</string>
                <string>--allow-uid</string>
                <string>\(allowUID)</string>
            </array>
            <key>RunAtLoad</key>
            <false/>
            <key>KeepAlive</key>
            <false/>
            <key>ProcessType</key>
            <string>Interactive</string>
            <key>StandardOutPath</key>
            <string>\(HelperK.logPath)</string>
            <key>StandardErrorPath</key>
            <string>\(HelperK.logPath)</string>
        </dict>
        </plist>
        """
    }

    /// 把待安装的两个文件落到用户目录（非特权即可），后续由特权步骤搬进系统目录
    static func stage() throws -> (helper: String, plist: String) {
        guard let src = HelperChannel.binarySource else {
            throw TZError.shell("Файл autoz-helper не найден в приложении. Повторите сборку")
        }
        let dir = K.appSupport + "/install"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let h = dir + "/autoz-helper"
        let p = dir + "/\(HelperK.label).plist"
        try? FileManager.default.removeItem(atPath: h)
        try FileManager.default.copyItem(atPath: src, toPath: h)
        try plistXML(allowUID: getuid()).write(toFile: p, atomically: true, encoding: .utf8)
        log("Файлы установки подготовлены: \(h) / \(p)")
        return (h, p)
    }

    static func installSteps(staged: (helper: String, plist: String)) -> [PrivStep] {
        [
            PrivStep("/bin/mkdir", ["-p", "/usr/local/libexec"]),
            PrivStep("/bin/cp", [staged.helper, HelperK.binPath]),
            PrivStep("/usr/sbin/chown", ["root:wheel", HelperK.binPath]),
            PrivStep("/bin/chmod", ["755", HelperK.binPath]),
            PrivStep("/bin/cp", [staged.plist, HelperK.plistPath]),
            PrivStep("/usr/sbin/chown", ["root:wheel", HelperK.plistPath]),
            PrivStep("/bin/chmod", ["644", HelperK.plistPath]),
            PrivStep("/bin/launchctl", ["bootout", "system/\(HelperK.label)"],
                     note: "Ошибка допустима, если служба не загружена", ignoreFailure: true),
            // 必须在 bootstrap 之前清旧 socket —— 放在后面会把 launchd 刚建好的 socket 删掉
            PrivStep("/bin/rm", ["-f", HelperK.socketPath],
                     note: "Удалить старый сокет, чтобы launchd создал новый", ignoreFailure: true),
            PrivStep("/bin/launchctl", ["bootstrap", "system", HelperK.plistPath]),
        ]
    }

    /// 卸载只允许动这三个白名单路径
    static let removablePaths = [HelperK.plistPath, HelperK.binPath, HelperK.socketPath]

    static func uninstallSteps() -> [PrivStep] {
        [
            PrivStep("/bin/launchctl", ["bootout", "system/\(HelperK.label)"],
                     note: "Ошибка допустима, если служба не загружена", ignoreFailure: true),
            PrivStep("/bin/rm", ["-f", HelperK.plistPath]),
            PrivStep("/bin/rm", ["-f", HelperK.binPath]),
            PrivStep("/bin/rm", ["-f", HelperK.socketPath], ignoreFailure: true),
        ]
    }

    /// 安装后等 socket 就绪并 ping 通（launchd 建 socket 需要一点时间）
    static func waitUntilReady(seconds: Double = 8) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if HelperChannel.ping() != nil { return true }
            Thread.sleep(forTimeInterval: 0.4)
        }
        return false
    }

    static func install() -> (ok: Bool, text: String) {
        guard HelperChannel.binarySource != nil else {
            return (false, "Файл autoz-helper не найден. Выполните ./build.sh")
        }
        if HelperChannel.ping() != nil {
            return (true, "Помощник уже работает; повторная установка не требуется.")
        }
        let staged: (helper: String, plist: String)
        do { staged = try stage() } catch { return (false, error.localizedDescription) }

        let r = runPrivilegedPlan(installSteps(staged: staged), reason: "Установка помощника")
        if r.cancelled { return (false, "Авторизация отменена. Помощник не установлен; для смены пояса по-прежнему нужен пароль.") }
        if !r.ok { return (false, "Ошибка установки: \(r.summary)") }

        if waitUntilReady() {
            return (true, "Помощник установлен. Часовой пояс можно менять без запроса пароля, в том числе после перезагрузки.")
        }
        return (false, "Файлы установлены, но помощник не отвечает. Проверьте журнал \(HelperK.logPath) или перезагрузите Mac.")
    }

    static func uninstall() -> (ok: Bool, text: String) {
        let r = runPrivilegedPlan(uninstallSteps(), reason: "Удаление помощника")
        if r.cancelled { return (false, "Авторизация отменена. Помощник не удалён.") }
        if !r.ok { return (false, "Ошибка удаления: \(r.summary)") }
        let leftovers = removablePaths.filter { FileManager.default.fileExists(atPath: $0) }
        if leftovers.isEmpty {
            return (true, "Помощник удалён. Для каждой смены пояса снова потребуется пароль.")
        }
        return (false, "Некоторые файлы остались: \(leftovers.joined(separator: ", "))")
    }
}

// MARK: - 提权后端

enum PrivBackend: String {
    case helper      = "helper"       // Без запроса пароля助手 (默认): 装过就零弹窗
    case native      = "native"       // 一次性授权: Security.framework
    case appleScript = "appleScript"  // 一次性授权: osascript
    var label: String {
        switch self {
        case .helper:      return "Помощник (рекомендуется)"
        case .native:      return "Запрос пароля · Security.framework"
        case .appleScript: return "Запрос пароля · AppleScript"
        }
    }
    var short: String {
        switch self {
        case .helper:      return "Без запроса пароля"
        case .native:      return "Security.framework"
        case .appleScript: return "AppleScript"
        }
    }
}

/// 以 argv 数组直接执行系统二进制（不经过 shell，因此没有任何字符串注入面）
func execPrivileged(_ auth: AuthorizationRef, _ tool: String, _ args: [String]) -> Int32 {
    var cargs: [UnsafeMutablePointer<CChar>?] = args.map { strdup($0) }
    cargs.append(nil)
    defer { for p in cargs where p != nil { free(p) } }
    return tool.withCString { t in
        cargs.withUnsafeMutableBufferPointer { buf in
            tzExecPriv(UnsafeMutableRawPointer(auth), t, buf.baseAddress)
        }
    }
}

/// 一次性授权路径会执行的特权命令（纯描述，供 --plan 审查；argv 直传、不经 shell）
func zoneSteps(zoneID: String, autoTZ: Bool?) -> [PrivStep] {
    var steps: [PrivStep] = []
    if let a = autoTZ {
        steps.append(PrivStep("/usr/bin/defaults",
                              ["write", K.autoTZPlist, "Active", "-bool", a ? "true" : "false"]))
    }
    steps.append(PrivStep("/usr/sbin/systemsetup", ["-settimezone", zoneID]))
    steps.append(PrivStep("/bin/ln", ["-sfn", K.zoneRoot + zoneID, "/etc/localtime"],
                          note: "Резервный способ, если systemsetup не сработал"))
    steps.append(PrivStep("/usr/bin/notifyutil", ["-p", "com.apple.system.timezone"]))
    return steps
}

/// 统一校验：不信任何通道的自报，直接读 /etc/localtime 复核
func verifyZone(_ zoneID: String) -> ApplyOutcome {
    let now = systemZoneID()
    if now == zoneID { return .changed(zoneID) }
    if let a = TimeZone(identifier: now), let b = TimeZone(identifier: zoneID),
       a.secondsFromGMT(for: Date()) == b.secondsFromGMT(for: Date()) {
        return .changed(zoneID)
    }
    return .failed("Проверка после записи не пройдена (/etc/localtime → \(now.isEmpty ? "неизвестно" : now))")
}

/// 设置系统时区（可选同时设自动时区开关）。
/// 通道优先级：免授权助手（零弹窗） → 一次性授权（原生 Security.framework → AppleScript）
func applySystemZone(_ zoneID: String, autoTZ: Bool? = nil) -> ApplyOutcome {
    guard isValidZoneID(zoneID) else {
        return .failed("Некорректный идентификатор пояса: \(zoneID)")
    }
    let needZone = systemZoneID() != zoneID
    let needAuto = autoTZ.map { autoTimeZoneEnabled() != $0 } ?? false
    if !needZone && !needAuto {
        return .already(zoneID)
    }

    // ---------- 通道 0：免授权助手（装过就不弹框）----------
    if Store.shared.privBackend == .helper {
        if HelperChannel.socketExists {
            if let r = HelperChannel.setZone(zoneID, auto: needAuto ? autoTZ : nil) {
                if r.ok {
                    Store.shared.lastBackend = "helper (без запроса пароля)"
                    log("Помощник выполнил запрос: \(r.msg) → zone=\(r.zone ?? "?") auto=\(r.auto.map(String.init) ?? "-")")
                    return verifyZone(zoneID)
                }
                // 助手明确拒绝或执行失败 → 直接报错。不再弹授权框：明知失败还打扰用户没有意义
                Store.shared.lastBackend = "helper (ошибка)"
                log("Ошибка помощника: \(r.msg)")
                return .failed(r.msg.isEmpty ? "Помощник отклонил запрос (пояс может отсутствовать в списке разрешённых)" : r.msg)
            }
            log("Сокет помощника есть, но ответа нет → запрос пароля")
        } else {
            log("Помощник не установлен → запрос пароля администратора")
        }
    }

    // ---------- 通道 1/2：一次性授权 ----------
    let r = runPrivilegedPlan(zoneSteps(zoneID: zoneID, autoTZ: needAuto ? autoTZ : nil),
                             reason: "Установить системный пояс → \(zoneID)")
    if r.cancelled { return .cancelled }
    if !r.ok { return .failed(r.summary) }
    return verifyZone(zoneID)
}

// MARK: - 时间格式

func displayTimeZone() -> TimeZone {
    TimeZone(identifier: Store.shared.displayZone) ?? beijingZone()
}

func beijingZone() -> TimeZone {
    TimeZone(identifier: K.beijingID) ?? TimeZone(secondsFromGMT: 8 * 3600)!
}

/// 把系统「24 小时制」强制偏好的覆盖逻辑套到模板上
private func applyHourOverride(_ pattern: String) -> String {
    var p = pattern
    let global = UserDefaults.standard.persistentDomain(forName: UserDefaults.globalDomain)
    if let forced = global?["AppleICUForce24HourTime"] as? Bool {
        if forced {
            p = p.replacingOccurrences(of: "a", with: "")
                 .replacingOccurrences(of: "h", with: "H")
        } else if !p.contains("a") {
            p = p.replacingOccurrences(of: "H", with: "h") + " a"
        }
        p = p.trimmingCharacters(in: .whitespaces)
    }
    return p
}

/// 菜单栏标题格式：**跟随系统菜单栏时钟**（日期 + 星期 + 时间）
/// 实测 zh_CN 下模板 "MMMdEEEjmm" → "M月d日 EEE HH:mm" → 渲染「9月23日 周三 10:04」，
/// 与系统自带时钟「9月23日 周三 09:53」完全同款。
func titlePattern(showSeconds: Bool) -> String {
    let raw = DateFormatter.dateFormat(fromTemplate: "MMMdEEEjmm" + (showSeconds ? "ss" : ""),
                                       options: 0, locale: Locale.current)
        ?? (showSeconds ? "EEE, d MMM HH:mm:ss" : "EEE, d MMM HH:mm")
    return applyHourOverride(raw)
}

/// 仅时间的格式（菜单里用 —— 标题已经带日期了，不必重复）
func clockPattern(showSeconds: Bool) -> String {
    let raw = DateFormatter.dateFormat(fromTemplate: "jmm" + (showSeconds ? "ss" : ""),
                                       options: 0, locale: Locale.current)
        ?? (showSeconds ? "HH:mm:ss" : "HH:mm")
    return applyHourOverride(raw)
}

func formatter(pattern: String, zone: TimeZone) -> DateFormatter {
    let f = DateFormatter()
    f.locale = Locale.current
    f.timeZone = zone
    f.dateFormat = pattern
    return f
}

// MARK: - Русский интерфейс
// Даты и названия часовых поясов в меню и настройках используют ru_RU.
// Часы в строке меню сохраняют системную локаль и настройку 12/24 часов.
let uiLocale = Locale(identifier: "ru_RU")

func uiPattern(_ template: String, fallback: String) -> String {
    DateFormatter.dateFormat(fromTemplate: template, options: 0, locale: uiLocale) ?? fallback
}

/// 固定 zh_CN 的格式化器（窗口状态表与下拉菜单共用）
func uiFormatter(pattern: String, zone: TimeZone) -> DateFormatter {
    let f = DateFormatter()
    f.locale = uiLocale
    f.timeZone = zone
    f.dateFormat = pattern
    return f
}

/// Время выбранного пояса в строке меню, в системном формате.
func displayTimeText(showSeconds: Bool, at date: Date = Date(), zone: TimeZone = displayTimeZone()) -> String {
    formatter(pattern: titlePattern(showSeconds: showSeconds), zone: zone).string(from: date)
}

/// Время выбранного пояса для статусной строки меню.
func displayClockText(showSeconds: Bool, at date: Date = Date(), zone: TimeZone = displayTimeZone()) -> String {
    let p = uiPattern("jmm" + (showSeconds ? "ss" : ""), fallback: showSeconds ? "HH:mm:ss" : "HH:mm")
    return uiFormatter(pattern: p, zone: zone).string(from: date)
}

func displayDateText(at date: Date = Date(), zone: TimeZone = displayTimeZone()) -> String {
    uiFormatter(pattern: uiPattern("yMMMdEEE", fallback: "EEE, d MMM yyyy"),
                zone: zone).string(from: date)
}

/// Отличается ли выбранное время от системного в текущий момент.
func isOffSystemZone() -> Bool {
    let sys = systemTimeZone()
    return sys.secondsFromGMT(for: Date()) != displayTimeZone().secondsFromGMT(for: Date())
}

// MARK: - 时区标识（当地时间 / 字母缩写 / UTC 偏移）

/// 秒偏移 → "UTC+8" / "UTC-7" / "UTC+5:30" / "UTC"
func utcOffsetText(seconds: Int) -> String {
    if seconds == 0 { return "UTC" }
    let sign = seconds < 0 ? "-" : "+"
    let a = abs(seconds)
    let h = a / 3600, m = (a % 3600) / 60
    return m == 0 ? "UTC\(sign)\(h)" : String(format: "UTC%@%d:%02d", sign, h, m)
}

/// 时区的**字母缩写**：PDT / PST / EST / EDT / BST …（按该时刻是否夏令时挑选）
///
/// 注意 `TimeZone.abbreviation(for:)` 在本机返回的是 "GMT+8"、"GMT-7" 这种，
/// **拿不到字母缩写**，所以必须走 ICU 的 localizedName。
/// 另外 ICU 对没有通行字母缩写的时区（Asia/Shanghai、Asia/Tokyo、Asia/Kolkata）
/// 会故意返回 "GMT+8" 之类以避开歧义（CST 既可能是中国标准时间也可能是美国中部时间），
/// 这种情况返回 nil，由调用方统一用 UTC 偏移展示，不长出两串重复信息。
func zoneLetterAbbrev(_ tz: TimeZone, at date: Date = Date()) -> String? {
    let style: TimeZone.NameStyle = tz.isDaylightSavingTime(for: date) ? .shortDaylightSaving : .shortStandard
    guard let n = tz.localizedName(for: style, locale: Locale(identifier: "en_US")), !n.isEmpty else { return nil }
    if n.hasPrefix("GMT") || n.hasPrefix("UTC") { return nil }
    return n
}

/// 时区徽标："PDT (UTC-7)"；拿不到字母缩写时只给 "UTC-7"
func zoneBadge(_ tz: TimeZone, at date: Date = Date()) -> String {
    let off = utcOffsetText(seconds: tz.secondsFromGMT(for: date))
    guard let a = zoneLetterAbbrev(tz, at: date) else { return off }
    return "\(a) (\(off))"
}

/// 任意时区的「日期 + 星期 + 时间」，模板与菜单栏标题一致（12/24 小时偏好一并继承）
func zonedTimeText(_ tz: TimeZone, showSeconds: Bool, at date: Date = Date()) -> String {
    formatter(pattern: titlePattern(showSeconds: showSeconds), zone: tz).string(from: date)
}

/// Разница во времени относительно выбранного пояса часов.
func zoneDeltaText(_ tz: TimeZone, relativeTo reference: TimeZone = displayTimeZone(), at date: Date = Date()) -> String {
    let mins = (tz.secondsFromGMT(for: date) - reference.secondsFromGMT(for: date)) / 60
    let referenceName = utcOffsetText(seconds: reference.secondsFromGMT(for: date))
    if mins == 0 { return "Совпадает с \(referenceName)" }
    let a = abs(mins), h = a / 60, m = a % 60
    var amount = ""
    if h > 0 { amount += "\(h) ч" }
    if m > 0 { amount += (h > 0 ? " " : "") + "\(m) мин" }
    return (mins > 0 ? "Впереди \(referenceName) на " : "Позади \(referenceName) на ") + amount
}

/// 相对东八区的时差，**紧凑写法**：`-15h` / `+1h` / `-2.5h`；一致时返回空串。
/// 只出现在「是否有差别」这一行（2026-10-02 用户要求：别散在时区行的小字里，
/// 把时区行留给"哪个区 + 几点"）。
func zoneDeltaShort(_ tz: TimeZone, relativeTo reference: TimeZone = displayTimeZone(), at date: Date = Date()) -> String {
    let mins = (tz.secondsFromGMT(for: date) - reference.secondsFromGMT(for: date)) / 60
    if mins == 0 { return "" }
    let sign = mins < 0 ? "-" : "+"
    let a = Double(abs(mins)) / 60
    return a == a.rounded() ? "\(sign)\(Int(a))h" : String(format: "%@%.1fh", sign, a)
}

/// 时区的中文名（ICU 通用名）：中国标准时间 / 北美太平洋时间 / 英国时间 …
/// 拿不到就退回 IANA id，避免界面上出现空白。
func localizedZoneName(_ tz: TimeZone) -> String {
    let ru = uiLocale
    return tz.localizedName(for: .generic, locale: ru)
        ?? tz.localizedName(for: .standard, locale: ru)
        ?? tz.identifier
}

/// 时区徽章："CST · UTC+8" / "PDT · UTC-7" / "UTC+5:30"
///
/// 与 zoneBadge 只差一处：**东八区强制给 CST**。ICU 对 Asia/Shanghai 会刻意返回 GMT+8
/// 来规避「CST 到底是哪国标准时间」的歧义，所以 zoneBadge 里它只剩 UTC+8；
/// 但界面上这一行永远带着「中国标准时间」的名字，上下文无歧义，补 CST 更好认。
func zoneChipText(_ tz: TimeZone, at date: Date = Date()) -> String {
    let off = utcOffsetText(seconds: tz.secondsFromGMT(for: date))
    if tz.identifier == K.beijingID { return "CST · \(off)" }
    guard let a = zoneLetterAbbrev(tz, at: date) else { return off }
    return "\(a) · \(off)"
}

/// 仅日期 + 星期（"10月3日 周六"）—— 状态表时间列的上半行。
/// locale 固定 zh_CN：与同一张表里的中文标签保持一致，不随系统语言漂成 "Sat, Oct 3"。
func zonedDateText(_ tz: TimeZone, at date: Date = Date()) -> String {
    uiFormatter(pattern: uiPattern("MMMdEEE", fallback: "EEE, d MMM"), zone: tz).string(from: date)
}

/// 仅时刻（"17:35:54"）—— 状态表时间列的下半行。**始终带秒**：
/// 两个时区的时间要在同一屏上对着看，差几秒也能看出来。
func zonedClockText(_ tz: TimeZone, at date: Date = Date()) -> String {
    uiFormatter(pattern: uiPattern("jmmss", fallback: "HH:mm:ss"), zone: tz).string(from: date)
}

/// 时区整行标识：中文名 · 字母缩写 · UTC 偏移（菜单与高级配置窗口共用同一口径）
func zoneLineText(_ tz: TimeZone, at date: Date = Date()) -> String {
    "\(localizedZoneName(tz)) · \(zoneChipText(tz, at: date))"
}

/// 出口行尾注：出口时区与系统时区**不同**时补上「那边的时间 + 徽标」——
/// 只写时区名的话还得自己换算，等于没有参考；相同时返回空串，不重复。
func exitZoneSuffix(exitZone: TimeZone, systemZone: TimeZone, at date: Date = Date()) -> String {
    guard exitZone.secondsFromGMT(for: date) != systemZone.secondsFromGMT(for: date) else { return "" }
    return "   \(zonedClockText(exitZone, at: date)) \(zoneChipText(exitZone, at: date))"
}

/// 归位时区选择器里的条目文本：「Asia/Shanghai    中国标准时间 · CST · UTC+8」
func zonePickerItem(_ id: String, at date: Date = Date()) -> String {
    guard let tz = TimeZone(identifier: id) else { return id }
    return "\(id)    \(zoneLineText(tz, at: date))"
}

/// 把选择器里的用户输入解析成合法 IANA 标识。
/// 两种输入都要认：从列表里选的整行（取第一段）、手敲的片段（模糊匹配，**唯一命中**才认，
/// 避免 "san" 这种一下命中十几个的歧义输入被猜错）。
func zoneIDFromPickerInput(_ raw: String) -> String? {
    let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return nil }
    if let first = trimmed.split(whereSeparator: { $0 == " " || $0 == "\t" }).first.map(String.init),
       TimeZone(identifier: first) != nil {
        return first
    }
    let key = trimmed.lowercased()
    let hits = TimeZone.knownTimeZoneIdentifiers.filter { $0.lowercased().contains(key) }
    return hits.count == 1 ? hits[0] : nil
}

/// 系统时区对象：优先用 /etc/localtime 解析出的 id 构造（`TimeZone.current` 有时滞后），
/// 拿不到就退回进程缓存的那个。
func systemTimeZone() -> TimeZone {
    let id = systemZoneID()
    if !id.isEmpty, let tz = TimeZone(identifier: id) { return tz }
    return TimeZone.current
}

/// 时区标识自测：全部用**固定时间戳**断言，结果不随当天日期漂移。
/// 覆盖「菜单里能同时看到时区标识与该地区的当地时间」这条用户明确提出的诉求。
func runTZSelfTest() -> Int {
    var pass = 0, fail = 0
    func yes(_ name: String, _ condition: Bool, _ detail: String = "") {
        if condition { pass += 1; print("  ✓ \(name)") }
        else { fail += 1; print("  ✗ \(name): \(detail)") }
    }
    func eq(_ name: String, _ got: String, _ want: String) {
        yes(name, got == want, "получено «\(got)», ожидалось «\(want)»")
    }
    func tz(_ id: String) -> TimeZone { TimeZone(identifier: id)! }
    let winter = Date(timeIntervalSince1970: 1768478400) // 2026-01-15 12:00 UTC
    let summer = Date(timeIntervalSince1970: 1782907200) // 2026-07-01 12:00 UTC

    print("── Смещения UTC и сезонные сокращения ──")
    for (seconds, expected) in [(28800, "UTC+8"), (-25200, "UTC-7"), (19800, "UTC+5:30"), (0, "UTC")] {
        eq("Смещение \(seconds)", utcOffsetText(seconds: seconds), expected)
    }
    for (id, date, expected) in [
        ("America/Los_Angeles", winter, "PST (UTC-8)"),
        ("America/Los_Angeles", summer, "PDT (UTC-7)"),
        ("America/New_York", summer, "EDT (UTC-4)"),
        ("America/Chicago", winter, "CST (UTC-6)"),
        ("Asia/Shanghai", winter, "UTC+8"), ("Asia/Tokyo", winter, "UTC+9"),
        ("Australia/Sydney", winter, "UTC+11"), ("Europe/London", summer, "UTC+1")
    ] { eq("\(id): \(expected)", zoneBadge(tz(id), at: date), expected) }
    eq("Фиксированный пояс", zoneBadge(TimeZone(secondsFromGMT: -25200)!, at: winter), "UTC-7")

    print("── Русские подписи разницы во времени ──")
    for (id, date, expected) in [
        ("America/Los_Angeles", winter, "Позади UTC+8 на 16 ч"),
        ("America/Los_Angeles", summer, "Позади UTC+8 на 15 ч"),
        ("Asia/Tokyo", winter, "Впереди UTC+8 на 1 ч"),
        ("Asia/Shanghai", winter, "Совпадает с UTC+8"),
        ("Asia/Kolkata", winter, "Позади UTC+8 на 2 ч 30 мин")
    ] { eq(id, zoneDeltaText(tz(id), relativeTo: beijingZone(), at: date), expected) }
    for (id, date, expected) in [
        ("America/Los_Angeles", summer, "-15h"), ("America/Los_Angeles", winter, "-16h"),
        ("Asia/Tokyo", winter, "+1h"), ("Asia/Kolkata", winter, "-2.5h"), ("Asia/Shanghai", winter, "")
    ] { eq("Краткая разница: \(id)", zoneDeltaShort(tz(id), relativeTo: beijingZone(), at: date), expected) }

    print("── Местное время, русские даты и названия ──")
    let bj = zonedTimeText(beijingZone(), showSeconds: false, at: winter)
    let tokyo = zonedTimeText(tz("Asia/Tokyo"), showSeconds: false, at: winter)
    let la = zonedTimeText(tz("America/Los_Angeles"), showSeconds: false, at: winter)
    yes("Токио отличается от Лос-Анджелеса", tokyo != la)
    yes("Токио отличается от Пекина", tokyo != bj)
    eq("Одинаковый пояс — одинаковое время", zonedTimeText(tz("Asia/Shanghai"), showSeconds: false, at: winter), bj)
    eq("Одинаковые пояса без повтора времени", exitZoneSuffix(exitZone: tz("America/Los_Angeles"), systemZone: tz("America/Los_Angeles"), at: winter), "")
    let suffix = exitZoneSuffix(exitZone: beijingZone(), systemZone: tz("America/Los_Angeles"), at: winter)
    yes("Другой пояс содержит UTC+8", suffix.contains("UTC+8"))
    yes("Другой пояс содержит время", suffix.contains(":"))
    yes("Название Пекина по-русски", localizedZoneName(beijingZone()).range(of: #"[А-Яа-яЁё]"#, options: .regularExpression) != nil)
    yes("Название Лос-Анджелеса по-русски", localizedZoneName(tz("America/Los_Angeles")).range(of: #"[А-Яа-яЁё]"#, options: .regularExpression) != nil)
    eq("Значок Пекина", zoneChipText(beijingZone(), at: winter), "CST · UTC+8")
    eq("Значок Лос-Анджелеса летом", zoneChipText(tz("America/Los_Angeles"), at: summer), "PDT · UTC-7")
    eq("Значок Токио", zoneChipText(tz("Asia/Tokyo"), at: winter), "UTC+9")
    let bjClock = zonedClockText(beijingZone(), at: winter)
    yes("Часы Пекина и Лос-Анджелеса отличаются", bjClock != zonedClockText(tz("America/Los_Angeles"), at: winter))
    yes("Время содержит секунды", bjClock.filter { $0 == ":" }.count == 2)
    let date = zonedDateText(beijingZone(), at: winter)
    yes("Дата на русском", date.contains("янв") && date.contains("15"), date)

    print("── Выбранный пояс часов ──")
    let suiteName = "autoz.selftest.\(UUID().uuidString)"
    let defaults = UserDefaults(suiteName: suiteName)!
    defer { defaults.removePersistentDomain(forName: suiteName) }
    let isolated = Store(defaults: defaults)
    let previousHome = isolated.homeZone
    let previousSync = isolated.syncEnabled
    eq("Прежний пояс сохранён по умолчанию", isolated.displayZone, K.beijingID)
    isolated.displayZone = "Europe/Istanbul"
    eq("Выбор сохраняется в настройках", Store(defaults: defaults).displayZone, "Europe/Istanbul")
    eq("Домашний пояс независим от часов", isolated.homeZone, previousHome)
    yes("Синхронизация не включается при выборе часов", isolated.syncEnabled == previousSync)
    isolated.displayZone = "Nope/Nowhere"
    eq("Неверный пояс не заменяет выбранный", isolated.displayZone, "Europe/Istanbul")
    defaults.set("../../etc/passwd", forKey: "displayZone")
    eq("Повреждённая настройка безопасно откатывается", isolated.displayZone, K.beijingID)
    for (id, date, expected) in [
        ("Europe/Istanbul", winter, "15:00:00"), ("Europe/Istanbul", summer, "15:00:00"),
        ("America/New_York", winter, "07:00:00"), ("America/New_York", summer, "08:00:00"),
        ("Asia/Kolkata", winter, "17:30:00")
    ] {
        eq("Часы: \(id)", displayClockText(showSeconds: true, at: date, zone: tz(id)), expected)
        eq("Заголовок: \(id)", displayTimeText(showSeconds: true, at: date, zone: tz(id)),
           zonedTimeText(tz(id), showSeconds: true, at: date))
    }
    eq("Разница относительно Турции", zoneDeltaShort(tz("Asia/Kolkata"), relativeTo: tz("Europe/Istanbul"), at: winter), "+2.5h")
    eq("Совпадающие пояса", zoneDeltaText(tz("Europe/Moscow"), relativeTo: tz("Europe/Istanbul"), at: winter), "Совпадает с UTC+3")
    eq("Выбор Istanbul", zoneIDFromPickerInput("istanbul") ?? "nil", "Europe/Istanbul")
    let late = Date(timeIntervalSince1970: 1768519800) // 2026-01-15 23:30 UTC
    eq("Дата часов после полуночи в Турции", displayDateText(at: late, zone: tz("Europe/Istanbul")),
       uiFormatter(pattern: uiPattern("yMMMdEEE", fallback: "EEE, d MMM yyyy"), zone: tz("Europe/Istanbul")).string(from: late))
    yes("Турция показывает следующий день", displayDateText(at: late, zone: tz("Europe/Istanbul")).contains("16 янв"))
    yes("Нью-Йорк показывает предыдущий день", displayDateText(at: late, zone: tz("America/New_York")).contains("15 янв"))

    print("── Меню и домашний пояс ──")
    let lines = AppDelegate().menuPreviewText().components(separatedBy: "\n")
    func lineHas(_ key: String, _ pattern: String) -> Bool {
        guard let line = lines.first(where: { $0.contains(key) }) else { return false }
        return line.range(of: pattern, options: .regularExpression) != nil
    }
    yes("Часы содержат время", lineHas("Часы  ", #"\d{1,3}:\d{2}:\d{2}"#))
    yes("Системный пояс содержит UTC", lineHas("Системный пояс", #"·\s*UTC([+-]\d+(:\d{2})?)?"#))
    yes("Системный пояс содержит местное время", lineHas("Системный пояс", #"\d{1,3}:\d{2}:\d{2}"#))
    if systemTimeZone().secondsFromGMT(for: Date()) != displayTimeZone().secondsFromGMT(for: Date()) {
        yes("Системный пояс содержит разницу", lineHas("Системный пояс", #"[+-]\d+(\.\d+)?h"#))
    }
    let homeID = Store.shared.homeZone
    let homeTZ = TimeZone(identifier: homeID)
    yes("Домашний пояс — допустимый IANA ID", homeTZ != nil, homeID)
    let homeLine = lines.first { $0.contains("Вернуть домашний пояс (") } ?? ""
    yes("Возврат домашнего пояса есть в меню", !homeLine.isEmpty)
    yes("Меню содержит название домашнего пояса", homeLine.contains(homeTZ.map { localizedZoneName($0) } ?? homeID))
    yes("Нет старого возврата к снимку", !lines.contains { $0.contains("Восстановить пояс до включения") })
    let item = zonePickerItem("Asia/Shanghai")
    eq("Выбранная строка → IANA", zoneIDFromPickerInput(item) ?? "nil", "Asia/Shanghai")
    eq("Часть названия → IANA", zoneIDFromPickerInput("shanghai") ?? "nil", "Asia/Shanghai")
    eq("Moscow → IANA", zoneIDFromPickerInput("moscow") ?? "nil", "Europe/Moscow")
    yes("Пустой запрос отклоняется", zoneIDFromPickerInput("   ") == nil)
    yes("Неоднозначный запрос отклоняется", zoneIDFromPickerInput("america") == nil)
    let menuText = lines.joined(separator: "\n")
    let han = try! NSRegularExpression(pattern: #"\p{script=Han}"#)
    yes("В меню нет китайского текста", han.numberOfMatches(in: menuText, range: NSRange(menuText.startIndex..<menuText.endIndex, in: menuText)) == 0, menuText)
    print("Результат: \(pass) пройдено, \(fail) ошибок")
    return fail == 0 ? 0 : 1
}

// MARK: - 状态存档

final class Store {
    static let shared = Store()
    private let d: UserDefaults

    init(defaults: UserDefaults = .standard) { d = defaults }

    /// Пояс часов независим от системного и домашнего поясов.
    /// Существующий вид часов сохраняется, пока пользователь не выберет другой пояс.
    var displayZone: String {
        get {
            guard let id = d.string(forKey: "displayZone"), isValidZoneID(id) else { return K.beijingID }
            return id
        }
        set {
            guard isValidZoneID(newValue) else { return }
            d.set(newValue, forKey: "displayZone")
        }
    }

    var syncEnabled: Bool {
        get { d.bool(forKey: "syncEnabled") }
        set { d.set(newValue, forKey: "syncEnabled") }
    }
    /// 菜单栏是否显示秒。默认 false —— 跟随系统时钟的样子（系统时钟不带秒）
    var showSeconds: Bool {
        get { d.object(forKey: "showSeconds") == nil ? false : d.bool(forKey: "showSeconds") }
        set { d.set(newValue, forKey: "showSeconds") }
    }
    var originalZone: String? {
        get { d.string(forKey: "originalZone") }
        set { d.set(newValue, forKey: "originalZone") }
    }
    var originalAutoTZ: Bool? {
        get { d.object(forKey: "originalAutoTZ") == nil ? nil : d.bool(forKey: "originalAutoTZ") }
        set {
            if let v = newValue { d.set(v, forKey: "originalAutoTZ") }
            else { d.removeObject(forKey: "originalAutoTZ") }
        }
    }

    /// **归位时区**：关闭「跟随出口 IP」或退出程序时，把系统时区写回这里。
    ///
    /// 默认东八区。早先的恢复目标是「开启同步那一刻的时区快照」（originalZone），
    /// 但那个快照会被跟随功能自己污染 —— 一旦某次跟随把系统时区改成了代理所在地，
    /// 之后重启再开同步，快照就把这个「假原始值」固化下来，用户点恢复反而回到代理时区
    /// （实测：快照被写成 America/Los_Angeles）。用户在中国，归位点本就该是
    /// 中国标准时间，所以改成显式配置（2026-10-11 定）。
    var homeZone: String {
        get { d.string(forKey: "homeZone") ?? K.beijingID }
        set { d.set(newValue, forKey: "homeZone") }
    }

    /// 关闭跟随 / 退出程序时是否自动归位（默认开）。
    /// 退出归位只在免授权助手就绪时执行，见 `applicationWillTerminate` ——
    /// 否则会在退出路径上弹授权框，把退出卡住。
    var autoHome: Bool {
        get { d.object(forKey: "autoHome") == nil ? true : d.bool(forKey: "autoHome") }
        set { d.set(newValue, forKey: "autoHome") }
    }
    var lastDetection: Detection? {
        get { d.data(forKey: "lastDetection").flatMap { try? JSONDecoder().decode(Detection.self, from: $0) } }
        set { d.set(newValue.flatMap { try? JSONEncoder().encode($0) }, forKey: "lastDetection") }
    }
    var lastSyncAt: Date? {
        get { d.object(forKey: "lastSyncAt") as? Date }
        set { d.set(newValue, forKey: "lastSyncAt") }
    }
    var lastAction: String {
        get { d.string(forKey: "lastAction") ?? "—" }
        set { d.set(newValue, forKey: "lastAction") }
    }
    /// 提权通道：默认「免授权助手」（装过就一直零弹窗），也可固定成一次性授权路线
    var privBackend: PrivBackend {
        get { d.string(forKey: "privBackend").flatMap { PrivBackend(rawValue: $0) } ?? .helper }
        set { d.set(newValue.rawValue, forKey: "privBackend") }
    }
    /// 配置版本，用于一次性迁移（v2：提权默认值由 native 改为 helper）
    var configVersion: Int {
        get { d.integer(forKey: "configVersion") }
        set { d.set(newValue, forKey: "configVersion") }
    }
    /// 上一次实际生效的后端（诊断用）
    var lastBackend: String {
        get { d.string(forKey: "lastBackend") ?? "—" }
        set { d.set(newValue, forKey: "lastBackend") }
    }

    /// 配置迁移：v2 把改时区通道默认值从「原生一次性授权」改成「免授权助手」。
    /// GUI 与 CLI 入口都会调用，避免两个入口看到不同的配置。
    func migrateIfNeeded() {
        if configVersion < 2 {
            log("Миграция v2: способ по умолчанию — помощник (прежнее значение \(privBackend.rawValue))")
            privBackend = .helper
            configVersion = 2
        }
        if configVersion < 3 {
            log("Миграция v3: формат часов совпадает с системным (дата, день недели, время без секунд)")
            showSeconds = false
            configVersion = 3
        }
        if configVersion < 4 {
            // 恢复目标由「开启前的快照」改为「归位时区」。快照可能已被跟随功能自己写脏
            // （例如写成代理所在地），留着既没用又容易被误读成"原始时区"，直接清掉。
            if let old = originalZone {
                log("Миграция v4: цель возврата — домашний пояс (\(homeZone)), удалён старый снимок \(old)")
                originalZone = nil
                originalAutoTZ = nil
            } else {
                log("Миграция v4: цель возврата — домашний пояс (\(homeZone))")
            }
            configVersion = 4
        }
    }
}

// MARK: - 菜单栏 App

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {

    private var statusItem: NSStatusItem!
    private var lastTitle = ""
    private var busy = false
    private let store = Store.shared

    func applicationDidFinishLaunching(_ n: Notification) {
        NSApp.setActivationPolicy(.accessory)

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let b = statusItem.button {
            b.imagePosition = .noImage
            b.font = menuBarTitleFont
        }
        let menu = NSMenu()
        menu.delegate = self
        statusItem.menu = menu

        for name in [NSNotification.Name.NSSystemTimeZoneDidChange,
                     NSLocale.currentLocaleDidChangeNotification,
                     NSNotification.Name.NSSystemClockDidChange] {
            NotificationCenter.default.addObserver(self, selector: #selector(externalChange),
                                                   name: name, object: nil)
        }

        // 配置迁移 v2：改时区通道默认值由「原生一次性授权」改为「免授权助手」
        store.migrateIfNeeded()

        // 首次运行把开机自启默认打开，省得用户哪天想起来才发现一直没开
        LoginItem.applyFirstRunDefault()

        // 高级配置窗口的动作交回本类实现（界面层不碰业务）
        AdvancedWindowController.shared.actions = self

        // 上次退出时同步是开着的 → 继续跟随
        if store.syncEnabled { startFollowing() }

        Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in self?.tick() }
        tick()
        // 用自绘图标替换 bundle 图标（构建时已写 AppIcon.icns，运行期再兜一层，保证 Dock/关于窗口一致）
        NSApp.applicationIconImage = Artwork.iconImage(size: 256)
        log("AutoZ \(K.version) запущен; системный пояс=\(systemZoneID()) автопояс=\(String(describing: autoTimeZoneEnabled())) способ=\(store.privBackend.rawValue)")
        // 助手探测放到主线程异步做，避免阻塞启动首帧
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            let ok = self.helperReady
            log("Состояние помощника: plist=\(HelperChannel.plistInstalled) bin=\(HelperChannel.binaryInstalled) socket=\(HelperChannel.socketExists) готов=\(ok)")
        }
        // 视觉自检开关：--show-menu 时自动把菜单弹出，便于截图核对版式（不必手点）
        if CommandLine.arguments.contains("--show-menu") {
            DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) { [weak self] in
                guard let self = self, let m = self.statusItem.menu else { return }
                // 用屏幕坐标（in: nil）弹出，比 in: button 更可靠；
                // Cocoa 原点在左下角，菜单栏项窗口底边就是菜单应该出现的位置
                let wf = self.statusItem.button?.window?.frame
                let at = NSPoint(x: wf?.minX ?? 2600, y: (wf?.minY ?? 1410) - 6)
                log("Проверка: открыто меню для снимка, позиция=\(NSStringFromPoint(at))")
                m.popUp(positioning: nil, at: at, in: nil)
            }
        }

        // 视觉自检开关：--show-console / --show-toast 分别自动打开高级配置窗口、弹一条通知，便于截图核对
        if CommandLine.arguments.contains("--show-console") {
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.8) {
                log("Проверка: открыто окно настроек для снимка")
                AdvancedWindowController.shared.show()

                // --snapshot-console <png>：把窗口内容离屏渲染存盘。
                // 比 screencapture 可靠得多 —— 不依赖屏幕录制权限、不受 Space / 遮挡影响，
                // 窗口在别的桌面也能拿到图（2026-10-02 实测 screencapture -R 只抓当前 Space，
                // 截出来是壁纸）。局限：NSVisualEffectView 的毛玻璃会渲染成透明，看版式足够。
                if let i = CommandLine.arguments.firstIndex(of: "--snapshot-console"),
                   i + 1 < CommandLine.arguments.count {
                    let path = CommandLine.arguments[i + 1]
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { snapshotConsole(to: path) }
                }
                // --snapshot-all <dir>：六个分区各截一张（验证"每一页都长得对"，
                // 比手动一个个点导航可靠，也快得多）
                if let i = CommandLine.arguments.firstIndex(of: "--snapshot-all"),
                   i + 1 < CommandLine.arguments.count {
                    let dir = CommandLine.arguments[i + 1]
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) { snapshotAllSections(into: dir) }
                }
            }
        }
        if CommandLine.arguments.contains("--show-toast") {
            DispatchQueue.main.asyncAfter(deadline: .now() + 2.6) {
                log("Проверка: показано уведомление для снимка")
                notify(title: "AutoZ: синхронизация завершена",
                       message: "Внешний IP 192.0.2.1 · Los Angeles, California, US → America/Los_Angeles")
            }
        }

        // 回归自检：从后台队列发通知（曾经这里会崩 —— 在非主线程创建 NSPanel）
        if CommandLine.arguments.contains("--show-toast-offthread") {
            DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
                DispatchQueue.global(qos: .userInitiated).async {
                    log("Проверка уведомления из фоновой очереди")
                    notify(title: "AutoZ: фоновое уведомление",
                           message: "Уведомление отправлено из фоновой очереди. Если оно видно, передача в главный поток работает.")
                }
            }
        }

        // 用户双击 .app 启动时（app 被激活到前台）给个反馈：本程序没有 Dock 图标，
        // 不打开点东西会显得"点了没反应"。由登录项/launchd 启动时不会被激活，不打扰。
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
            if NSApp.isActive, !CommandLine.arguments.contains("--show-console") {
                log("Ручной запуск → открыты настройки")
                AdvancedWindowController.shared.show()
            }
        }

        // 状态栏项自检：用程序内部数据确认它真的挂在菜单栏上（外部截图不可靠）
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in
            guard let self = self, let b = self.statusItem.button else {
                log("Проверка строки меню: кнопка отсутствует")
                return
            }
            log("Проверка строки меню: isVisible=\(self.statusItem.isVisible) length=\(String(format: "%.1f", self.statusItem.length)) "
                + "buttonFrame=\(NSStringFromRect(b.frame)) координаты экрана=\(b.window.map { NSStringFromRect($0.frame) } ?? "нет окна") "
                + "заголовок=\"\(b.attributedTitle.string)\" цвет=\(b.attributedTitle.length > 0 ? "\(b.attributedTitle.attribute(.foregroundColor, at: 0, effectiveRange: nil) ?? "нет")" : "нет")")
        }
    }

    func applicationWillTerminate(_ n: Notification) {
        log("AutoZ завершает работу")
        // 退出归位：把系统时区写回「归位时区」（默认东八区）。
        // 只在免授权助手就绪时做 —— 否则退出路径上会弹授权框，把退出卡住。
        guard store.syncEnabled, store.autoHome else {
            log("Возврат при выходе пропущен (синхронизация или автовозврат выключены)")
            return
        }
        let home = store.homeZone
        let cur = systemZoneID()
        guard cur != home else {
            log("Возврат при выходе: уже установлен \(home)")
            return
        }
        guard store.privBackend == .helper, HelperChannel.socketExists else {
            log("Возврат при выходе пропущен: помощник недоступен. Текущий пояс: \(cur), домашний: \(home)")
            return
        }
        switch applySystemZone(home, autoTZ: store.originalAutoTZ) {
        case .changed(let z): log("Возврат при выходе: \(cur) → \(z)")
        case .already(let z): log("Возврат при выходе: Уже установлен \(z)")
        case .cancelled:      log("Возврат при выходе: отменено")
        case .failed(let e):  log("Ошибка возврата при выходе: \(e)")
        }
    }

    // ---- 标题渲染 ----

    private func tick() {
        let showSec = store.showSeconds
        // 标题就是纯时间。早先前置过一个「◷」标识符，但它笔画极细、在菜单栏里几乎看不见，
        // 起不到辨识作用反而显脏，已去掉。
        let text = displayTimeText(showSeconds: showSec)
        let off = isOffSystemZone()
        // 不一致时标橙色而不是纯红：红色在彩色壁纸和深色菜单栏上容易过冲发闷，
        // 橙色同样一眼看得出「这不是本机时间」，又没那么刺眼。
        let color: NSColor = off ? .systemOrange : .labelColor

        let attrs: [NSAttributedString.Key: Any] = [
            .font: menuBarTitleFont,
            .foregroundColor: color,
        ]
        if text != lastTitle || statusItem.button?.attributedTitle.string.isEmpty == true {
            statusItem.button?.attributedTitle = NSAttributedString(string: text, attributes: attrs)
            lastTitle = text
        } else {
            // 颜色可能因系统时区变化而需刷新
            statusItem.button?.attributedTitle = NSAttributedString(string: text, attributes: attrs)
        }
        statusItem.button?.toolTip = tooltipText()
    }

    private func tooltipText() -> String {
        let sys = systemZoneID()
        let sysTZ = systemTimeZone()
        var lines = ["Часы: \(Store.shared.displayZone) · \(zoneBadge(displayTimeZone())) · \(displayTimeText(showSeconds: true))"]
        lines.append("Системный пояс: \(sys.isEmpty ? "неизвестно" : sys)   \(zoneBadge(sysTZ))")
        lines.append("Местное время: \(zonedTimeText(sysTZ, showSeconds: true))   \(zoneDeltaText(sysTZ))")
        if isOffSystemZone() {
            lines.append("⚠️ Часы показывают время другого часового пояса")
        }
        if let det = store.lastDetection {
            lines.append("Внешний IP: \(det.ip) \(det.locationText)")
            lines.append("Определённый пояс: \(det.zoneID)")
        }
        return lines.joined(separator: "\n")
    }

    @objc private func externalChange() {
        log("Смена пояса/региона → системный пояс=\(systemZoneID())")
        DispatchQueue.main.async {
            self.lastTitle = ""
            self.tick()
            self.rebuildMenu()
        }
    }

    // ---- 菜单 ----

    func menuWillOpen(_ menu: NSMenu) {
        rebuildMenu()
    }

    // ---- 菜单（数据驱动：先建行模型 → 再渲染；同一模型可打印成文本供审查）----
    //
    // 主次约定：顶部 3 行状态 → 两个主操作（加粗，同步 / 恢复）→ 免授权模式状态 →
    //          其余全部收进「更多」子菜单 → 退出。菜单整体控制在 10 行以内（不含子菜单）。

    enum RowStyle { case strong, info, primary, normal }

    enum MRow {
        case info(String, RowStyle)
        case action(title: String, sel: Selector?, enabled: Bool, checked: Bool, style: RowStyle, tip: String?)
        case submenu(title: String, rows: [MRow])
        case sep
    }

    /// 助手是否就绪（带 5s 缓存，避免每次开菜单都等一次 ping）
    private var helperReadyCache: (at: Date, ok: Bool)?
    private var helperReady: Bool {
        if let c = helperReadyCache, Date().timeIntervalSince(c.at) < 5 { return c.ok }
        let ok = HelperChannel.ping() != nil
        helperReadyCache = (Date(), ok)
        return ok
    }

    func menuModel() -> [MRow] {
        let sysTZ = systemTimeZone()
        let now = Date()
        var rows: [MRow] = []

        // ── 1. 状态三行，口径与高级配置窗口的状态表**共用同一批纯函数**
        //    （zoneLineText / zonedClockText / zonedDateText / zoneDeltaShort），
        //    免得两处各写一份而慢慢漂移。
        //    每行都带上「哪个区 + 几点几分 + 哪天」—— 只给 America/Los_Angeles
        //    这种名字等于没给参考，用户还得自己换算。
        rows.append(.info("Часы  \(zoneLineText(displayTimeZone(), at: now))   \(displayClockText(showSeconds: true))   \(zonedDateText(displayTimeZone(), at: now))", .strong))
        //    系统时区与出口时区**不可合并**：同步生效时两者相同，关掉同步就会分叉，都要留。
        let delta = zoneDeltaShort(sysTZ, at: now)
        rows.append(.info("Системный пояс  \(zoneLineText(sysTZ, at: now))"
                          + "   \(zonedClockText(sysTZ, at: now))   \(zonedDateText(sysTZ, at: now))"
                          + (delta.isEmpty ? "" : "   \(delta)"), .info))
        if let det = store.lastDetection {
            // 出口时区与系统时区不同（关掉同步后很常见）时，把那边的时间也带上。
            let suffix = TimeZone(identifier: det.zoneID)
                .map { exitZoneSuffix(exitZone: $0, systemZone: sysTZ, at: now) } ?? ""
            rows.append(.info("Внешний IP  \(det.ip) · \(det.locationText)  →  \(det.zoneID)" + suffix, .info))
        } else {
            rows.append(.info("Внешний IP  ещё не определён", .info))
        }

        rows.append(.sep)

        // ── 2. 主操作：把「同步开关 / 立即执行一次 / 回到归位时区」三件事分开，别再互相混
        let homeID = store.homeZone
        let homeTZ = TimeZone(identifier: homeID)
        let homeLabel = homeTZ.map { zoneLineText($0, at: now) } ?? homeID
        if store.syncEnabled {
            rows.append(.action(title: store.autoHome ? "Отключить синхронизацию и вернуть домашний пояс" : "Отключить синхронизацию (сохранить пояс)",
                                sel: #selector(toggleSync(_:)),
                                enabled: !busy, checked: true, style: .primary,
                                tip: store.autoHome
                                    ? "Отключить синхронизацию и вернуть домашний пояс (\(homeLabel))"
                                    : "Отключить синхронизацию и сохранить системный пояс (автовозврат выключен)"))
        } else {
            rows.append(.action(title: "Включить синхронизацию по IP", sel: #selector(toggleSync(_:)),
                                enabled: !busy, checked: false, style: .primary,
                                tip: "Определять часовой пояс системы по внешнему IP. С помощником запрос пароля не требуется"))
        }
        rows.append(.action(title: "Проверить и синхронизировать один раз", sel: #selector(checkAndSync(_:)),
                            enabled: !busy, checked: false, style: .normal,
                            tip: "Один раз проверить внешний IP и применить пояс (без помощника потребуется пароль)"))
        rows.append(.action(title: "Вернуть домашний пояс (\(homeLabel))",
                            sel: #selector(restoreHome(_:)), enabled: !busy,
                            checked: false, style: .primary,
                            tip: "Вернуть домашний пояс \(homeID), восстановить настройку автоматического пояса и отключить синхронизацию"))

        rows.append(.sep)

        // ── 3. 其余一切（关于、显示、通道、助手、诊断…）都在高级配置窗口里，菜单不再堆子菜单
        rows.append(.action(title: "Часовой пояс часов…", sel: #selector(chooseDisplayZone(_:)),
                            enabled: true, checked: false, style: .normal,
                            tip: "Выбрать время для часов в меню"))
        rows.append(.action(title: "Настройки…", sel: #selector(showConsole(_:)),
                            enabled: true, checked: false, style: .normal,
                            tip: "Часы в меню, авторизация, установка и удаление помощника, диагностика и сведения о программе"))

        rows.append(.sep)
        rows.append(.action(title: "Завершить AutoZ", sel: #selector(quitApp(_:)),
                            enabled: true, checked: false, style: .normal, tip: nil))

        if busy {
            rows.append(.sep)
            rows.append(.info("⏳ Проверка / ожидание авторизации…", .info))
        }
        return rows
    }

    private func attrs(style: RowStyle) -> [NSAttributedString.Key: Any] {
        switch style {
        case .strong:
            // 菜单项字号跟随系统（NSFont.menuFont(ofSize: 0) 也是 13）。早先写 12pt，
            // 和下面 13pt 的正常行并排时明显矮一截。
            return [.font: NSFont.monospacedDigitSystemFont(ofSize: 13, weight: .semibold),
                    .foregroundColor: NSColor.labelColor]
        case .info:
            return [.font: NSFont.systemFont(ofSize: 11),
                    .foregroundColor: NSColor.secondaryLabelColor]
        case .primary:
            return [.font: NSFont.systemFont(ofSize: 13, weight: .semibold),
                    .foregroundColor: NSColor.labelColor]
        case .normal:
            return [.font: NSFont.systemFont(ofSize: 13),
                    .foregroundColor: NSColor.labelColor]
        }
    }

    private func render(_ rows: [MRow], into menu: NSMenu) {
        for row in rows {
            switch row {
            case .sep:
                menu.addItem(.separator())

            case .info(let text, let style):
                let item = NSMenuItem(title: text, action: nil, keyEquivalent: "")
                item.isEnabled = false
                item.attributedTitle = NSAttributedString(string: text, attributes: attrs(style: style))
                menu.addItem(item)

            case .action(let title, let sel, let enabled, let checked, let style, let tip):
                let item = NSMenuItem(title: title, action: sel, keyEquivalent: "")
                item.target = self
                item.isEnabled = enabled
                item.state = checked ? .on : .off
                item.toolTip = tip
                item.attributedTitle = NSAttributedString(string: title, attributes: attrs(style: style))
                menu.addItem(item)

            case .submenu(let title, let sub):
                let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
                item.attributedTitle = NSAttributedString(string: title, attributes: attrs(style: .normal))
                let m = NSMenu()
                render(sub, into: m)
                item.submenu = m
                menu.addItem(item)
            }
        }
    }

    private func rebuildMenu() {
        guard let menu = statusItem.menu else { return }
        menu.removeAllItems()
        render(menuModel(), into: menu)
    }

    /// 把菜单渲染成文本（供 CLI --menu 审查，不用肉眼点菜单）
    func menuPreviewText() -> String {
        var out: [String] = []
        func walk(_ rows: [MRow], _ depth: Int) {
            let pad = String(repeating: "    ", count: depth)
            for r in rows {
                switch r {
                case .sep:
                    out.append(pad + "──────────────────────────")
                case .info(let t, let s):
                    out.append(pad + (s == .strong ? "[\(t)]" : "   \(t)"))
                case .action(let t, _, let en, let ck, let st, let tip):
                    let mark = ck ? "[✓] " : (en ? "" : "[недоступно] ")
                    let body = st == .primary ? "** \(t) **" : t
                    out.append(pad + mark + body + (tip != nil ? "   ⟨подсказка⟩" : ""))
                case .submenu(let t, let sub):
                    out.append(pad + "\(t) ▸")
                    walk(sub, depth + 1)
                }
            }
        }
        walk(menuModel(), 0)
        return out.joined(separator: "\n")
    }

    // ---- 自动跟随（同步开关打开时的后台行为）----
    //
    // 「开启同步」不能只是记一个状态：这里真的去跟随 ——
    //   · 网络变化（切 WiFi / 开 VPN）后延时 15 秒检测一次出口 IP
    //   · 另有 10 分钟兜底轮询，防止漏检
    // 装了免授权助手就静默应用；没装则只发通知提醒（后台自动动作不该突然冒出一个密码框）。

    private var followTimer: Timer?
    private var pathMonitor: NWPathMonitor?
    private var followInFlight = false

    private func startFollowing() {
        guard followTimer == nil else { return }
        if pathMonitor == nil {
            let m = NWPathMonitor()
            m.pathUpdateHandler = { [weak self] path in
                guard path.status == .satisfied else { return }
                DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
                    self?.followCheck(reason: "изменение сети")
                }
            }
            m.start(queue: DispatchQueue(label: "autoz.path"))
            pathMonitor = m
        }
        followTimer = Timer.scheduledTimer(withTimeInterval: 600, repeats: true) { [weak self] _ in
            self?.followCheck(reason: "таймер")
        }
        log("Автосинхронизация включена (при смене сети и каждые 10 минут)")
    }

    private func stopFollowing() {
        followTimer?.invalidate()
        followTimer = nil
        pathMonitor?.cancel()
        pathMonitor = nil
        log("Автосинхронизация остановлена")
    }

    /// 检测出口 IP 对应时区；与当前系统时区不同才动手
    private func followCheck(reason: String) {
        guard store.syncEnabled, !busy, !followInFlight else { return }
        followInFlight = true
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self = self else { return }
            let det = try? Checker.run()
            DispatchQueue.main.async {
                self.followInFlight = false
                guard let det = det else {
                    log("Автосинхронизация (\(reason))Проверка не удалась")
                    return
                }
                self.store.lastDetection = det
                let cur = systemZoneID()
                guard det.zoneID != cur else {
                    log("Автосинхронизация (\(reason)): по-прежнему \(cur), изменений не требуется")
                    return
                }
                if HelperChannel.socketExists {
                    log("Автосинхронизация (\(reason)): \(cur) → \(det.zoneID)")
                    let out = applySystemZone(det.zoneID, autoTZ: false)
                    switch out {
                    case .changed(let z):
                        self.store.lastAction = "Автосинхронизация → \(z)"
                        notify(title: "AutoZ: пояс обновлён по IP", message: "\(det.locationText) → Системный пояс установлен: \(z)")
                    case .failed(let e):
                        notify(title: "AutoZ: ошибка автосинхронизации", message: e)
                    default:
                        break
                    }
                } else {
                    self.store.lastAction = "Пояс по IP изменился: \(det.zoneID)(без применения)"
                    notify(title: "AutoZ: часовой пояс по IP изменился",
                           message: "\(det.locationText) → \(det.zoneID). Нажмите «Проверить и синхронизировать». Для автоматической смены установите помощник")
                }
                self.refresh()
            }
        }
    }

    // ---- 动作 ----

    @objc private func toggleSync(_ sender: NSMenuItem) {
        if store.syncEnabled {
            store.syncEnabled = false
            stopFollowing()
            let home = store.homeZone
            let cur = systemZoneID()
            // 关掉跟随 = 不再按出口 IP 走，顺手把系统时区写回归位时区（默认东八区）。
            // 只有「已经不在归位时区」且用户没关掉自动归位时才动手，否则纯关开关。
            if store.autoHome, cur != home {
                store.lastAction = "Синхронизация выключена, возврат → \(home)"
                log("Синхронизация выключена: возврат \(cur) → \(home)")
                notify(title: "AutoZ: синхронизация выключена",
                       message: "Синхронизация по IP выключена. Возвращается пояс \(home)…")
                after { [weak self] in
                    guard let self = self else { return }
                    switch applySystemZone(home, autoTZ: self.store.originalAutoTZ) {
                    case .changed(let z):
                        self.store.lastAction = "Синхронизация выключена → возвращён пояс \(z)"
                        log("После отключения возвращён пояс → \(z)")
                        notify(title: "AutoZ: домашний пояс восстановлен", message: "Системный пояс = \(z)")
                    case .already(let z):
                        log("После отключения: уже установлен \(z)")
                    case .cancelled:
                        notify(title: "AutoZ", message: "Отменено; системный пояс остался \(cur)")
                    case .failed(let e):
                        notify(title: "AutoZ: не удалось вернуть домашний пояс", message: e, sound: "Basso")
                    }
                }
                return
            }
            store.lastAction = "Синхронизация выключена (сохранён пояс \(cur))"
            log("Синхронизация выключена (системный пояс сохранён): autoHome=\(store.autoHome) текущий=\(cur) домашний=\(home)")
            let tip = store.autoHome
                ? ", уже установлен домашний пояс \(home)"
                : ", сохранён \(cur) (автовозврат выключен)"
            notify(title: "AutoZ: синхронизация выключена", message: "Синхронизация по IP выключена\(tip).")
            refresh()
        } else {
            store.syncEnabled = true
            if store.originalZone == nil {
                let cur = systemZoneID()
                store.originalZone = cur
                store.originalAutoTZ = autoTimeZoneEnabled()
                log("Сохранено исходное состояние: пояс=\(cur) автопояс=\(String(describing: autoTimeZoneEnabled()))")
            }
            store.lastAction = "Синхронизация включена"
            startFollowing()
            notify(title: "AutoZ: синхронизация включена", message: "Определение и установка часового пояса по внешнему IP…")
            perform(apply: true)
        }
        rebuildMenu()
    }

    @objc private func checkAndSync(_ sender: NSMenuItem) {
        if store.originalZone == nil {
            store.originalZone = systemZoneID()
            store.originalAutoTZ = autoTimeZoneEnabled()
        }
        store.lastAction = "Проверить и синхронизировать"
        perform(apply: true)
    }

    @objc private func checkOnly(_ sender: NSMenuItem) {
        store.lastAction = "Только проверить"
        perform(apply: false)
    }

    /// 回到归位时区：把系统时区写回 `homeZone`（默认东八区），还原「自动设置时区」开关，
    /// 并关闭同步。**不再使用「开启同步前的快照」** —— 那个值可能被跟随功能自己写脏。
    @objc private func restoreHome(_ sender: NSMenuItem) {
        let home = store.homeZone
        guard let tz = TimeZone(identifier: home) else {
            notify(title: "AutoZ: не удалось вернуть домашний пояс", message: "Некорректный идентификатор IANA домашнего пояса: \(home)", sound: "Basso")
            return
        }
        let name = localizedZoneName(tz)
        store.lastAction = "Ручной возврат \(home)"
        log("Ручной возврат → \(home) (\(name))")
        after { [weak self] in
            guard let self = self else { return }
            switch applySystemZone(home, autoTZ: self.store.originalAutoTZ) {
            case .changed(let z):
                self.store.lastAction = "Возвращён пояс \(z)"
                notify(title: "AutoZ: домашний пояс восстановлен", message: "Системный пояс = \(z) (\(name))")
                self.store.syncEnabled = false
                self.stopFollowing()
            case .already(let z):
                notify(title: "AutoZ", message: "Системный пояс уже установлен: \(z). Изменений не требуется.")
                self.store.syncEnabled = false
                self.stopFollowing()
            case .cancelled:
                notify(title: "AutoZ", message: "Отменено; системный пояс не изменён")
            case .failed(let e):
                notify(title: "AutoZ: не удалось вернуть домашний пояс", message: e, sound: "Basso")
            }
        }
    }

    /// 改「归位时区」。传进来的必须是合法 IANA 标识，否则拒绝并告知。
    @objc private func setHomeZone(_ id: String) {
        guard TimeZone(identifier: id) != nil else {
            notify(title: "AutoZ", message: "«\(id)» — некорректный идентификатор часового пояса", sound: "Basso")
            return
        }
        store.homeZone = id
        store.lastAction = "Домашний пояс → \(id)"
        log("Домашний пояс изменён: \(id)")
        refresh()
    }

    @objc private func setAutoHome(_ on: Bool) {
        store.autoHome = on
        store.lastAction = on ? "Автовозврат включён" : "Автовозврат выключен"
        log("Автовозврат → \(on ? "вкл." : "выкл.")")
        refresh()
    }

    @objc private func toggleSeconds(_ sender: NSMenuItem) {
        store.showSeconds.toggle()
        lastTitle = ""
        refresh()
    }

    @objc private func useHelperBackend(_ sender: NSMenuItem) {
        store.privBackend = .helper
        log("Способ смены пояса → \(store.privBackend.rawValue)")
        refresh()
    }

    @objc private func useNativeBackend(_ sender: NSMenuItem) {
        store.privBackend = .native
        log("Способ смены пояса → \(store.privBackend.rawValue)(пароль запрашивается каждый раз)")
        refresh()
    }

    @objc private func useAppleScriptBackend(_ sender: NSMenuItem) {
        store.privBackend = .appleScript
        log("Способ смены пояса → \(store.privBackend.rawValue)(пароль запрашивается каждый раз)")
        refresh()
    }

    /// 安装免授权助手：这是唯一还需要输一次密码的地方，之后改时区零弹窗
    @objc private func installHelper(_ sender: NSMenuItem) {
        log("Начало установки помощника")
        after { [weak self] in
            guard let self = self else { return }
            let r = HelperInstaller.install()
            self.helperReadyCache = nil
            self.store.lastAction = r.ok ? "Помощник установлен" : "Установка помощника не завершена"
            notify(title: r.ok ? "AutoZ: помощник готов" : "AutoZ: установка не завершена", message: r.text)
            self.refresh()
        }
    }

    @objc private func uninstallHelper(_ sender: NSMenuItem) {
        let a = NSAlert()
        a.messageText = "Удалить помощника?"
        a.informativeText = """
        Будут удалены три файла:
        ・\(HelperK.plistPath)
        ・\(HelperK.binPath)
        ・\(HelperK.socketPath)

        После удаления для каждой смены часового пояса потребуется пароль. Для удаления нужна авторизация администратора.
        """
        a.addButton(withTitle: "Отмена")
        a.addButton(withTitle: "Удалить")
        NSApp.activate(ignoringOtherApps: true)
        guard a.runModal() == .alertSecondButtonReturn else { return }

        after { [weak self] in
            guard let self = self else { return }
            let r = HelperInstaller.uninstall()
            self.helperReadyCache = nil
            self.store.lastAction = r.ok ? "Помощник удалён" : "Удаление помощника не завершено"
            notify(title: r.ok ? "AutoZ: помощник удалён" : "AutoZ: удаление не завершено", message: r.text)
            self.refresh()
        }
    }

    @objc private func openDateSettings(_ sender: NSMenuItem) {
        // 原生 API：NSWorkspace 打开系统设置深链（macOS 13+ 用 Settings 扩展 URL，旧系统回退到 preference pane）
        if !openDateAndTimeSettings() {
            log("Не удалось открыть настройки даты и времени")
            notify(title: "AutoZ", message: "Не удалось открыть системные настройки даты и времени", sound: nil)
        }
    }

    @objc private func copyDiagnostics(_ sender: NSMenuItem) {
        let text = diagnosticsText()
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        notify(title: "AutoZ", message: "Диагностика скопирована в буфер обмена", sound: nil)
    }

    @objc private func testNotification(_ sender: NSMenuItem) {
        notify(title: "AutoZ: проверка уведомлений",
               message: "Так выглядит уведомление о синхронизации. Его показывает само приложение")
    }

    private func diagnosticsText() -> String {
        var out: [String] = []
        out.append("AutoZ \(K.version) Диагностика  \(stamp(Date()))")
        out.append("Версия macOS: \(ProcessInfo.processInfo.operatingSystemVersionString)")
        out.append("Пояс часов: \(store.displayZone)")
        out.append("Часы в меню: \(displayTimeText(showSeconds: store.showSeconds))")
        out.append("Шаблон часов: \(titlePattern(showSeconds: store.showSeconds))  (формат системных часов)")
        out.append("Шаблон времени: \(clockPattern(showSeconds: store.showSeconds))  секунды=\(store.showSeconds)")
        out.append("Системный пояс: \(systemZoneID())")
        out.append("Автовыбор пояса: \(String(describing: autoTimeZoneEnabled()))")
        out.append("Синхронизация: \(store.syncEnabled ? "вкл." : "выкл.")  Домашний пояс: \(store.homeZone)"
                   + "  Автовозврат: \(store.autoHome ? "вкл." : "выкл.")")
        // 旧快照只作诊断留存，**不再是恢复目标**（可能被跟随功能自己写脏）
        out.append("Исходный снимок (для диагностики): \(store.originalZone ?? "нет")")
        out.append("Последнее действие: \(store.lastAction)")
        out.append("Способ смены пояса: \(store.privBackend.rawValue) (последний использованный: \(store.lastBackend))")
        out.append("Помощник: \(HelperChannel.statusText)")
        out.append("Автозапуск: \(LoginItem.statusText)")
        out.append("  \(LoginItem.plistURL.path)")
        out.append("  plist есть=\(HelperChannel.plistInstalled)  исполняемый файл есть=\(HelperChannel.binaryInstalled)  socket есть=\(HelperChannel.socketExists)")
        out.append("Уведомления: баннеры приложения (без системных разрешений, см. ui.swift)")
        if let d = store.lastDetection {
            out.append("Источник проверки: \(d.source)  \(stamp(d.fetchedAt))")
            out.append("Внешний IP: \(d.ip)  \(d.locationText)  \(d.org)")
            out.append("Определённый пояс: \(d.zoneID)  ← \(d.zoneSource)")
            out.append("Исходный ответ:\n\(d.rawJSON)")
        } else {
            out.append("Источник проверки: нет")
        }
        return out.joined(separator: "\n")
    }

    @objc private func chooseDisplayZone(_ sender: Any?) {
        AdvancedWindowController.shared.chooseDisplayZone()
    }

    @objc private func showConsole(_ sender: Any?) {
        // 高级配置窗口（见 ui.swift）：关于 + 全部次级操作，实底高对比
        AdvancedWindowController.shared.show()
    }

    @objc private func quitApp(_ sender: NSMenuItem) {
        NSApp.terminate(nil)
    }

    // ---- 检测流程 ----

    private func after(_ work: @escaping () -> Void) {
        busy = true
        rebuildMenu()
        DispatchQueue.global(qos: .userInitiated).async {
            work()
            DispatchQueue.main.async { self.busy = false; self.refresh() }
        }
    }

    private func perform(apply: Bool) {
        busy = true
        rebuildMenu()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            let outcome: ApplyOutcome?
            var detection: Detection?
            var errorText: String?
            do {
                let det = try Checker.run()
                detection = det
                log("Проверка выполнена: \(det.ip) \(det.locationText) → \(det.zoneID) (\(det.zoneSource))")
                if apply {
                    // 同步时一并关闭「自动设置时区」，否则系统会用定位把时区改回去
                    outcome = applySystemZone(det.zoneID, autoTZ: false)
                } else {
                    outcome = nil
                }
            } catch {
                errorText = error.localizedDescription
                outcome = nil
                log("Проверка не удалась: \(errorText ?? "?")")
            }

            DispatchQueue.main.async {
                self.busy = false
                if let det = detection { self.store.lastDetection = det }

                if let err = errorText {
                    self.store.lastAction = "Проверка не удалась"
                    notify(title: "AutoZ Проверка не удалась", message: err)
                    self.refresh()
                    return
                }
                guard let det = detection else { self.refresh(); return }

                if !apply {
                    self.store.lastAction = "Только проверить: \(det.zoneID)"
                    notify(title: "AutoZ: результат проверки",
                           message: "\(det.ip) · \(det.locationText) → \(det.zoneID)(системный пояс не изменён)")
                    self.refresh()
                    return
                }

                switch outcome! {
                case .changed(let z):
                    self.store.lastSyncAt = Date()
                    self.store.lastAction = "Установлен пояс \(z)"
                    notify(title: "AutoZ: часовой пояс обновлён",
                           message: "\(det.ip) · \(det.locationText) → \(z). Автоматический выбор пояса macOS отключён, чтобы система не вернула прежнее значение.")
                    self.rebuildMenu()
                    self.refresh()
                case .already(let z):
                    self.store.lastSyncAt = Date()
                    self.store.lastAction = "Уже установлен \(z)"
                    notify(title: "AutoZ", message: "Системный пояс уже установлен: \(z). Изменений не требуется.")
                    self.refresh()
                case .cancelled:
                    self.store.lastAction = "Авторизация отменена"
                    notify(title: "AutoZ", message: "Авторизация отменена; системный пояс не изменён (цель: \(det.zoneID))")
                    self.refresh()
                case .failed(let e):
                    self.store.lastAction = "Ошибка установки пояса"
                    notify(title: "AutoZ: ошибка установки пояса", message: e)
                    self.refresh()
                }
            }
        }
    }

    private func refresh() {
        // 有些调用点在工作队列上（例如 after{} 里的收尾），而菜单/窗口都是 UI，必须回主线程
        guard Thread.isMainThread else {
            DispatchQueue.main.async { [weak self] in self?.refresh() }
            return
        }
        lastTitle = ""
        tick()
        rebuildMenu()
        // 高级配置窗口开着就一起刷新（界面层不反向调用业务，所以由这里统一推）
        if AdvancedWindowController.shared.window?.isVisible == true {
            AdvancedWindowController.shared.refresh()
        }
    }
}

// MARK: - 命令行模式（便于脚本/测试）

func runCLI(_ args: [String]) -> Int32 {
    func pr(_ s: String) { print(s) }
    Store.shared.migrateIfNeeded()

    switch args[0] {
    case "--check", "--query":
        do {
            let d = try Checker.run()
            pr("ip:        \(d.ip)")
            pr("location:  \(d.locationText)")
            pr("org:       \(d.org)")
            pr("source:    \(d.source)")
            pr("timezone:  \(d.zoneID)")
            pr("how:       \(d.zoneSource)")
            return 0
        } catch { pr("ERROR: \(error.localizedDescription)"); return 2 }

    case "--apply":
        do {
            let d = try Checker.run()
            pr("Проверка: \(d.ip) \(d.locationText) → \(d.zoneID) (\(d.zoneSource))")
            switch applySystemZone(d.zoneID) {
            case .changed(let z): pr("OK: Системный пояс установлен: \(z)"); return 0
            case .already(let z): pr("OK: Системный пояс уже установлен: \(z)"); return 0
            case .cancelled:      pr("CANCELLED: нет разрешения"); return 3
            case .failed(let e):  pr("FAILED: \(e)"); return 4
            }
        } catch { pr("ERROR: \(error.localizedDescription)"); return 2 }

    case "--set":
        guard args.count > 1, isValidZoneID(args[1]) else { pr("Использование: AutoZ --set <пояс IANA, например Europe/Moscow>"); return 1 }
        switch applySystemZone(args[1]) {
        case .changed(let z): pr("OK: Системный пояс установлен: \(z)"); return 0
        case .already(let z): pr("OK: Системный пояс уже установлен: \(z)"); return 0
        case .cancelled:      pr("CANCELLED"); return 3
        case .failed(let e):  pr("FAILED: \(e)"); return 4
        }

    case "--system":
        pr("Системный пояс:   \(systemZoneID())")
        pr("Автовыбор пояса: \(String(describing: autoTimeZoneEnabled()))")
        pr("Кеш процесса:   \(TimeZone.current.identifier)")
        return 0

    case "--format":
        pr("locale:        \(Locale.current.identifier)")
        pr("Секунды:        \(Store.shared.showSeconds)")
        pr("Шаблон часов:      \(titlePattern(showSeconds: Store.shared.showSeconds))   ← формат системных часов")
        pr("Шаблон времени:      \(clockPattern(showSeconds: Store.shared.showSeconds))")
        pr("Текст часов:      \(displayTimeText(showSeconds: Store.shared.showSeconds))")
        pr("Время с секундами:    \(displayClockText(showSeconds: true))")
        pr("Пояс часов: \(Store.shared.displayZone)")
        pr("Дата:    \(displayDateText())")
        pr("Отличается от системы:  \(isOffSystemZone() ? "да (оранжевые часы)" : "нет (обычный цвет)")")
        return 0

    case "--icon-preview":
        guard args.count > 2, let size = Double(args[2]) else {
            pr("Использование: AutoZ --icon-preview <файл.png> <размер>"); return 1
        }
        guard let data = Artwork.pngData(size: CGFloat(size)) else { pr("Ошибка отрисовки"); return 1 }
        do {
            try data.write(to: URL(fileURLWithPath: args[1]))
            pr("Экспортирован \(args[1]) (\(Int(size))px)")
            return 0
        } catch { pr("Ошибка записи: \(error)"); return 1 }

    case "--notify-test":
        pr("Баннеры уведомлений видны только в работающем приложении.")
        pr("  · Если приложение запущено: «Настройки → Диагностика → Проверить уведомления»")
        pr("  · Запустить проверку: /usr/bin/open /Applications/AutoZ.app --args --notify-test")
        notify(title: "AutoZ: проверка уведомлений", message: "Уведомление из командной строки (баннер виден только в приложении)")
        pr("Запись добавлена в \(K.logPath).")
        return 0

    case "--print-osa", "--plan":
        let zone = args.count > 1 ? args[1] : (try? Checker.run().zoneID) ?? K.beijingID
        guard isValidZoneID(zone) else { pr("Некорректный пояс: \(zone)"); return 1 }
        pr("Целевой пояс:      \(zone)")
        pr("Текущий системный пояс:  \(systemZoneID())")
        pr("Автовыбор пояса:  \(String(describing: autoTimeZoneEnabled()))")
        pr("Цель символической ссылки:    \(K.zoneRoot)\(zone)")
        pr("")
        pr("=== Способ 0: помощник (без запроса пароля)===")
        pr("socket: \(HelperK.socketPath)  есть=\(HelperChannel.socketExists)")
        pr("plist:  \(HelperK.plistPath)  есть=\(HelperChannel.plistInstalled)")
        pr("Исполняемый файл: \(HelperK.binPath)  есть=\(HelperChannel.binaryInstalled)")
        if let r = HelperChannel.ping() {
            pr("ping:   ✓ \(r.msg)  пояс по данным помощника=\(r.raw["zone"] as? String ?? "?")")
            pr("Будет отправлено: {\"cmd\":\"set_zone\",\"zone\":\"\(zone)\",\"auto\":false}")
        } else {
            pr("ping:   ✗ нет ответа → способ 1/2 с запросом пароля")
        }
        pr("")
        pr("=== Способ 1: Security.framework (аргументы argv, без оболочки)===")
        pr("AuthorizationCreate(nil, nil, [.interactionAllowed, .extendRights, .preAuthorize])")
        for c in zoneSteps(zoneID: zone, autoTZ: false) {
            pr("  \(c.display)\(c.note.map { "   ← \($0)" } ?? "")")
        }
        pr("")
        pr("=== Способ 2: AppleScript (резервный) ===")
        pr(buildOsaCommand(zoneID: zone, autoTZ: false))
        pr("")
        pr("(Показан только план; команды с правами администратора не выполнялись)")
        return 0

    case "--menu":
        pr(AppDelegate().menuPreviewText())
        return 0

    case "--tz-selftest":
        return Int32(runTZSelfTest())

    case "--helper-status":
        pr("Состояние помощника")
        pr("  Метка:     \(HelperK.label)")
        pr("  socket:   \(HelperK.socketPath)  есть=\(HelperChannel.socketExists)")
        pr("  plist:    \(HelperK.plistPath)  есть=\(HelperChannel.plistInstalled)")
        pr("  Исполняемый файл:   \(HelperK.binPath)  есть=\(HelperChannel.binaryInstalled)")
        pr("  Источник установки: \(HelperChannel.binarySource ?? "(не найден; повторите сборку)")")
        pr("  allow uid: \(getuid())")
        pr("  Журнал:     \(HelperK.logPath)")
        if let r = HelperChannel.ping() {
            pr("  ping:     ✓ \(r.msg)  версия=\(r.raw["version"] as? String ?? "?")  PID помощника=\(r.raw["pid"] as? Int ?? -1)")
            pr("            пояс по данным помощника=\(r.raw["zone"] as? String ?? "?")  автопояс=\(r.raw["auto"].map { "\($0)" } ?? "-")")
            pr("  Итог: помощник включён; смена пояса без запроса пароля")
        } else {
            pr("  ping:     ✗ нет ответа")
            pr("  Итог: помощник выключен; для смены пояса нужен пароль. Установка: «Настройки → Авторизация»")
        }
        return 0

    case "--helper-plan":
        pr("=== Установка помощника: план команд с правами администратора (без выполнения)===")
        if let src = HelperChannel.binarySource {
            let staged = (helper: K.appSupport + "/install/autoz-helper",
                          plist: K.appSupport + "/install/\(HelperK.label).plist")
            pr("① Без прав администратора (каталог пользователя)")
            pr("  cp \(src) → \(staged.helper)")
            pr("  Записать \(staged.plist) (allow-uid=\(getuid()))")
            pr("② С правами администратора (один запрос пароля)")
            for (i, s) in HelperInstaller.installSteps(staged: staged).enumerated() {
                pr("  \(i + 1). \(s.display)\(s.note.map { "   ← \($0)" } ?? "")")
            }
        } else {
            pr("autoz-helper не найден. Выполните ./build.sh")
        }
        pr("")
        pr("=== Удаление: план команд с правами администратора (без выполнения)===")
        for (i, s) in HelperInstaller.uninstallSteps().enumerated() {
            pr("  \(i + 1). \(s.display)\(s.note.map { "   ← \($0)" } ?? "")")
        }
        pr("")
        pr("Удаление затрагивает только три разрешённых пути:")
        for p in HelperInstaller.removablePaths { pr("  \(p)") }
        return 0

    case "--helper-install":
        let r = HelperInstaller.install()
        pr(r.ok ? "OK: \(r.text)" : "Не завершено: \(r.text)")
        return r.ok ? 0 : 4

    case "--helper-uninstall":
        let r = HelperInstaller.uninstall()
        pr(r.ok ? "OK: \(r.text)" : "Не завершено: \(r.text)")
        return r.ok ? 0 : 4

    case "--login-status":
        pr("Автозапуск: \(LoginItem.statusText)")
        pr("  Файл настроек: \(LoginItem.plistURL.path)\(LoginItem.isEnabled ? "" : "(отсутствует)")")
        pr("  Приложение: \(Bundle.main.bundlePath)")
        pr("  Применение: при следующем входе в систему (launchd читает LaunchAgents при входе)")
        pr("  Отключение: AutoZ --login-disable или «Системные настройки → Основные → Объекты входа»")
        return 0

    // 注意：args 是去掉程序名之后的参数，单参数的开关里**不能**写 args[1]，会越界崩溃。
    // 所以这里拆成两个 case，而不是合并后用 args[1] 判断。
    case "--login-enable":
        if let err = LoginItem.set(true) {
            pr("Не удалось включить автозапуск: \(err)")
            return 4
        }
        pr("OK: Автозапуск → \(LoginItem.statusText)")
        return 0

    case "--login-disable":
        if let err = LoginItem.set(false) {
            pr("Не удалось выключить автозапуск: \(err)")
            return 4
        }
        pr("OK: Автозапуск → \(LoginItem.statusText)")
        return 0

    case "--notify-status":
        pr("bundle id: \(bundleID)")
        pr("Уведомления: баннеры приложения (ToastCenter, см. Sources/ui.swift)")
        pr("  · Без osascript и системных разрешений на уведомления")
        pr("  · События: результат синхронизации, возврат пояса, установка/удаление помощника")
        pr("  · Проверка: «Настройки → Диагностика → Проверить уведомления» или --notify-test")
        pr("  · История: ~/Library/Logs/AutoZ.log (в том числе без интерфейса)")
        return 0

    case "--backend":
        guard args.count > 1, let b = PrivBackend(rawValue: args[1]) else {
            pr("Использование: AutoZ --backend helper|native|appleScript"); return 1
        }
        Store.shared.privBackend = b
        pr("Способ смены пояса: \(b.label)")
        return 0

    case "--version":
        pr("AutoZ \(K.version)"); return 0

    default:
        pr("""
        AutoZ \(K.version) — \(appDisplayName) (\(appTagline))

        Использование:
          AutoZ                  Запустить часы в строке меню
          AutoZ --check          Определить внешний IP и пояс, не меняя систему
          AutoZ --apply          Определить и применить часовой пояс по IP
          AutoZ --set <zone>     Установить пояс IANA (например, Europe/Moscow)
          AutoZ --system         Показать системный пояс и автовыбор пояса
          AutoZ --format         Показать формат, пояс и текст часов
          AutoZ --menu           Показать структуру меню
          AutoZ --tz-selftest    Проверить часовые пояса и русский интерфейс без изменения системы
          AutoZ --plan [zone]    Показать план смены пояса без выполнения
          AutoZ --backend <b>    Способ авторизации: helper | native | appleScript
          AutoZ --notify-status  Сведения об уведомлениях
          AutoZ --notify-test    Проверить уведомления
          AutoZ --login-status   Состояние автозапуска
          AutoZ --login-enable   Включить автозапуск (из /Applications)
          AutoZ --login-disable  Выключить автозапуск
          AutoZ --icon-preview <png> <size>  Экспортировать значок

        Помощник (после установки смена пояса без запроса пароля):
          AutoZ --helper-status     Состояние помощника и ping
          AutoZ --helper-plan       План установки/удаления без выполнения
          AutoZ --helper-install    Установить (один запрос пароля администратора)
          AutoZ --helper-uninstall  Удалить (один запрос пароля администратора)
          autoz-helper --selftest    11 проверок протокола и безопасности без изменения системы
        """)
        return 0
    }
}

// MARK: - 入口

// --show-* 是 GUI 自检开关，不能当成 CLI 参数（否则会被 CLI 分支吃掉直接退出）
let guiSwitches: Set<String> = ["--show-menu", "--show-console", "--show-toast", "--show-toast-offthread",
                                "--snapshot-console", "--snapshot-all"]
let argv = Array(CommandLine.arguments.dropFirst()).filter { !guiSwitches.contains($0) }
if let first = argv.first, first.hasPrefix("-") {
    exit(runCLI(argv))
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()

/// 六个分区各离屏渲染一张（`--snapshot-all <dir>`）。配合 --show-console 使用。
/// 每一页之间留一拍让 Auto Layout 落地，否则后一页可能还是上一页的版式。
func snapshotAllSections(into dir: String) {
    let names = ["01-sync", "02-menubar", "03-login", "04-backend", "05-maintenance", "06-about"]
    func shoot(_ i: Int) {
        guard i < names.count else {
            log("Проверка: снимки шести разделов сохранены → \(dir)")
            return
        }
        AdvancedWindowController.shared.selectSectionForProbe(i)
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
            AdvancedWindowController.shared.window?.contentView?.layoutSubtreeIfNeeded()
            snapshotConsole(to: "\(dir)/\(names[i]).png")
            shoot(i + 1)
        }
    }
    shoot(0)
}

/// 把高级配置窗口的内容离屏渲染成 PNG（UI 自检用，见 `--snapshot-console`）。
/// 为什么不直接 screencapture：后者要屏幕录制权限，而且 `-R` 只抓当前 Space ——
/// 窗口在别的桌面时截到的是壁纸。离屏渲染两者都不需要。
func snapshotConsole(to path: String) {
    guard let w = AdvancedWindowController.shared.window, let v = w.contentView else {
        log("Снимок не создан: окно отсутствует")
        return
    }
    guard let rep = v.bitmapImageRepForCachingDisplay(in: v.bounds) else {
        log("Снимок не создан: ошибка создания изображения")
        return
    }
    v.cacheDisplay(in: v.bounds, to: rep)
    guard let data = rep.representation(using: .png, properties: [:]) else {
        log("Снимок не создан: ошибка кодирования PNG")
        return
    }
    do {
        try data.write(to: URL(fileURLWithPath: path))
        log("Снимок окна сохранён → \(path)  (\(rep.pixelsWide)×\(rep.pixelsHigh))")
    } catch {
        log("Ошибка сохранения снимка: \(error.localizedDescription)")
    }
}

// MARK: - 高级配置窗口的动作实现
//
// 界面层（ui.swift）只负责转发，业务逻辑仍然全在 AppDelegate 里 —— 不为了好看把逻辑搬散。

extension AppDelegate: AutoZActions {

    func azToggleSync()      { toggleSync(NSMenuItem()) }
    func azCheckAndSync()    { store.lastAction = "Проверить и синхронизировать"; perform(apply: true) }
    func azCheckOnly()       { store.lastAction = "Только проверить"; perform(apply: false) }
    func azRestoreHome()     { restoreHome(NSMenuItem()) }
    func azSetHomeZone(_ id: String) { setHomeZone(id) }

    func azSetDisplayZone(_ id: String) {
        guard isValidZoneID(id), store.displayZone != id else { return }
        store.displayZone = id
        log("Пояс часов в меню → \(id)")
        lastTitle = ""
        refresh()
    }

    func azSetAutoHome(_ on: Bool) {
        guard store.autoHome != on else { return }
        setAutoHome(on)
    }

    func azSetShowSeconds(_ on: Bool) {
        guard store.showSeconds != on else { return }
        store.showSeconds = on
        lastTitle = ""
        refresh()
    }

    /// 开关开机自启。状态以系统登录项为准，不额外在 UserDefaults 存一份 ——
    /// 否则用户在「系统设置」里手动改掉之后就对不上了。
    func azSetLaunchAtLogin(_ on: Bool) {
        if let err = LoginItem.set(on) {
            log("Не удалось изменить автозапуск (\(on ? "вкл." : "выкл.")): \(err)")
            notify(title: "Ошибка настройки автозапуска", message: err, sound: "Basso")
        } else {
            log("Автозапуск → \(LoginItem.statusText)")
            notify(title: on ? "Автозапуск включён" : "Автозапуск выключен", message: LoginItem.statusText)
        }
        refresh()
    }

    func azInstallHelper()   { installHelper(NSMenuItem()) }
    func azUninstallHelper() { uninstallHelper(NSMenuItem()) }

    func azSetBackend(_ backend: PrivBackend) {
        store.privBackend = backend
        log("Способ смены пояса → \(backend.rawValue)")
        refresh()
    }

    func azOpenDateSettings() { _ = openDateAndTimeSettings() }
    func azOpenCalendar()     { _ = openCalendarApp() }
    func azCopyDiagnostics()  { copyDiagnostics(NSMenuItem()) }
    func azTestNotification() { testNotification(NSMenuItem()) }

    func azOpenLog() {
        let url = URL(fileURLWithPath: K.logPath)
        if FileManager.default.fileExists(atPath: K.logPath) {
            NSWorkspace.shared.open(url)
        } else {
            NSWorkspace.shared.activateFileViewerSelecting([url])
        }
    }
}

// autoz-helper — AutoZ 的特权助手（由 launchd 按需拉起，不常驻）
//
// 为什么需要它：
//   macOS 上改系统时区必须 root。没有 helper 时，每次改都要弹一次系统认证框
//   （Security.framework 或 AppleScript），实测凭证不会跨调用复用。
//   装一个 launchd 托管的 helper 后，改时区走 Unix socket 本地通信，**不再弹任何框**。
//
// 安全设计（窄接口，不做成 root 后门）：
//   1. 只监听 /var/run/cn.y10n.autoz.sock，且**只接受四个指令**：
//      ping / state / set_zone / set_auto。不接受任何自由形式的命令或路径。
//   2. 校验 socket 对端 uid（getpeereid）必须等于安装时记录的 uid，否则直接拒绝。
//   3. 时区必须同时通过「字符白名单正则 + 无 .. + 无前导 / + 在 zoneinfo 下真实存在」，
//      因此不存在路径穿越，也不接受任意字符串。
//   4. 不使用 shell：所有系统二进制都以 argv 数组直接 exec，没有注入面。
//   5. 空闲 20s 自动退出 → 不常驻内存（launchd 下次连接时再拉起）。
//
// 自测（不需要 root）：
//   ./autoz-helper --selftest        起临时 socket 自连，跑 9 项协议与安全用例
//   ./autoz-helper --print-plan      打印会对系统做什么（不执行）
//
// 手工（需要 root）：
//   sudo /usr/local/libexec/autoz-helper --set-zone Asia/Tokyo --auto false

import Foundation
import Darwin

// MARK: - 常量

enum H {
    static let label      = "cn.y10n.autoz.helper"
    static let socketPath = "/var/run/cn.y10n.autoz.sock"
    static let plistPath  = "/Library/LaunchDaemons/cn.y10n.autoz.helper.plist"
    static let binPath    = "/usr/local/libexec/autoz-helper"
    static let logPath    = "/var/log/cn.y10n.autoz.helper.log"
    static let zoneRoots  = ["/var/db/timezone/zoneinfo/", "/usr/share/zoneinfo/"]
    static let autoPlist  = "/Library/Preferences/com.apple.timezone.auto"
    static let version    = "1.1.0"
    /// 空闲多久没连接就退出（不常驻）
    static let idleSeconds: Int32 = 20
    /// 单次进程寿命硬上限（防御性）
    static let maxLifeSeconds: TimeInterval = 120
}

// MARK: - 日志

private let logQueue = DispatchQueue(label: "autoz.helper.log")

func hlog(_ msg: String) {
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_US_POSIX")
    f.dateFormat = "yyyy-MM-dd HH:mm:ss"
    let line = "[\(f.string(from: Date()))] [pid \(getpid())] \(msg)\n"
    let data = Data(line.utf8)
    logQueue.sync {
        let fm = FileManager.default
        if !fm.fileExists(atPath: H.logPath) { fm.createFile(atPath: H.logPath, contents: nil) }
        if let h = FileHandle(forWritingAtPath: H.logPath) {
            h.seekToEndOfFile()
            h.write(data)
            try? h.close()
        } else {
            FileHandle.standardError.write(data)   // 非 root 测试时落到 stderr
        }
    }
}

// MARK: - 子进程（argv 直传，不经 shell）

@discardableResult
func run(_ path: String, _ args: [String]) -> (status: Int32, out: String, err: String) {
    guard FileManager.default.isExecutableFile(atPath: path) else { return (-1, "", "Файл не исполняемый: \(path)") }
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let op = Pipe(), ep = Pipe()
    p.standardOutput = op
    p.standardError = ep
    do { try p.run() } catch { return (-1, "", "\(error)") }
    let od = op.fileHandleForReading.readDataToEndOfFile()
    let ed = ep.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return (p.terminationStatus,
            String(decoding: od, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines),
            String(decoding: ed, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
}

// MARK: - 系统状态读写

/// 读 /etc/localtime 软链 → IANA 时区
func readZone() -> String {
    guard let link = try? FileManager.default.destinationOfSymbolicLink(atPath: "/etc/localtime") else { return "" }
    for root in H.zoneRoots where link.hasPrefix(root) {
        return String(link.dropFirst(root.count))
    }
    return link
}

func readAuto() -> Bool? {
    let r = run("/usr/bin/defaults", ["read", H.autoPlist, "Active"])
    guard r.status == 0 else { return nil }
    switch r.out.lowercased() {
    case "1", "true", "yes":  return true
    case "0", "false", "no":  return false
    default:                  return nil
    }
}

// MARK: - 时区校验（安全边界）

/// 只允许字母/数字/_/+/-/. 与最多 4 段路径，长度 ≤64
let zonePattern = try! NSRegularExpression(pattern: "^[A-Za-z0-9_+.-]{1,32}(/[A-Za-z0-9_+.-]{1,32}){0,3}$")

/// 合法时区返回它在 zoneinfo 下的真实路径，否则 nil
func zoneFile(_ zone: String) -> String? {
    guard !zone.isEmpty, zone.count <= 64,
          !zone.contains(".."), !zone.hasPrefix("/"), !zone.hasSuffix("/") else { return nil }
    let range = NSRange(zone.startIndex..<zone.endIndex, in: zone)
    guard zonePattern.firstMatch(in: zone, range: range) != nil else { return nil }
    for root in H.zoneRoots {
        let p = root + zone
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: p, isDirectory: &isDir), !isDir.boolValue {
            return p
        }
    }
    return nil
}

// MARK: - 核心动作

struct ApplyResult {
    var ok: Bool
    var changed: Bool
    var zone: String
    var auto: Bool?
    var msg: String
    var steps: [String]

    var json: [String: Any] {
        var d: [String: Any] = ["ok": ok, "changed": changed, "zone": zone,
                                "msg": msg, "steps": steps]
        if let a = auto { d["auto"] = a }
        return d
    }
}

/// 设置时区（可选同时设自动时区开关）。
/// dryRun=true 时只做校验与计划，不碰系统。
func applyZone(_ zone: String, auto: Bool?, dryRun: Bool) -> ApplyResult {
    guard let zfile = zoneFile(zone) else {
        return ApplyResult(ok: false, changed: false, zone: zone, auto: auto,
                           msg: "Пояс недопустим или отсутствует (проверка списка разрешённых): \(zone)", steps: [])
    }
    var steps: [String] = []
    var changed = false
    let cur = readZone()

    if cur != zone {
        changed = true
        steps.append("/usr/sbin/systemsetup -settimezone \(zone)")
        if !dryRun {
            let r = run("/usr/sbin/systemsetup", ["-settimezone", zone])
            hlog("systemsetup -settimezone \(zone) -> \(r.status) \(r.err)")
            if readZone() != zone {
                // 兜底：原子替换软链（先建临时链，再 rename 覆盖，无中间态）
                steps.append("Атомарная замена /etc/localtime → \(zfile)")
                let tmp = "/etc/localtime.autoz.tmp"
                try? FileManager.default.removeItem(atPath: tmp)
                do {
                    try FileManager.default.createSymbolicLink(atPath: tmp, withDestinationPath: zfile)
                } catch {
                    // 失败时上报「实际仍是哪个时区」，不要用请求值冒充现状
                    return ApplyResult(ok: false, changed: false, zone: readZone(), auto: readAuto(),
                                       msg: "Не удалось создать временную символическую ссылку: \(error.localizedDescription)", steps: steps)
                }
                if rename(tmp, "/etc/localtime") != 0 {
                    let e = String(cString: strerror(errno))
                    try? FileManager.default.removeItem(atPath: tmp)
                    return ApplyResult(ok: false, changed: false, zone: readZone(), auto: readAuto(),
                                       msg: "Не удалось заменить /etc/localtime: \(e)", steps: steps)
                }
                hlog("/etc/localtime атомарно заменён → \(zfile)")
            }
        }
    }

    if let a = auto, readAuto() != a {
        changed = true
        steps.append("/usr/bin/defaults write \(H.autoPlist) Active -bool \(a)")
        if !dryRun {
            let r = run("/usr/bin/defaults", ["write", H.autoPlist, "Active", "-bool", a ? "true" : "false"])
            hlog("defaults write auto=\(a) -> \(r.status) \(r.err)")
        }
    }

    if changed {
        steps.append("/usr/bin/notifyutil -p com.apple.system.timezone")
        if !dryRun {
            _ = run("/usr/bin/notifyutil", ["-p", "com.apple.system.timezone"])
        }
    }

    if dryRun {
        return ApplyResult(ok: true, changed: changed, zone: zone, auto: auto,
                           msg: changed ? "Пробный режим: \(steps.count) действий, без выполнения" : "Пробный режим: изменений не требуется",
                           steps: steps)
    }

    // 不信自己的自报，直接复核
    let nowZone = readZone()
    guard nowZone == zone else {
        return ApplyResult(ok: false, changed: changed, zone: nowZone, auto: readAuto(),
                           msg: "Проверка после записи не пройдена (/etc/localtime → \(nowZone.isEmpty ? "неизвестно" : nowZone))",
                           steps: steps)
    }
    let nowAuto = readAuto()
    return ApplyResult(ok: true, changed: changed, zone: nowZone, auto: nowAuto ?? auto,
                       msg: changed ? "Применено" : "Уже установлено целевое состояние", steps: steps)
}

// MARK: - Unix socket

func makeAddr(_ path: String) -> (sockaddr_un, socklen_t) {
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let cap = MemoryLayout.size(ofValue: addr.sun_path)
    withUnsafeMutablePointer(to: &addr.sun_path) { p in
        p.withMemoryRebound(to: CChar.self, capacity: cap) { dst in
            _ = strlcpy(dst, path, cap)
        }
    }
    let len = socklen_t(MemoryLayout<sa_family_t>.size + path.utf8.count + 1)
    return (addr, len)
}

func bindListen(_ path: String) -> Int32 {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { hlog("Ошибка socket(), errno=\(errno)"); return -1 }
    var (addr, len) = makeAddr(path)
    let rc = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, len) }
    }
    guard rc == 0 else {
        hlog("bind(\(path)) ошибка, errno=\(errno) \(String(cString: strerror(errno)))")
        close(fd)
        return -1
    }
    guard listen(fd, 16) == 0 else {
        hlog("listen ошибка, errno=\(errno)")
        close(fd)
        return -1
    }
    // 让同机普通用户能连（真正的门禁是下面的 uid 校验）
    chmod(path, 0o666)
    return fd
}

/// launchd 以 Sockets 键按需拉起时，用它取回监听 fd
@_silgen_name("launch_activate_socket")
func launch_activate_socket(_ name: UnsafePointer<CChar>,
                            _ fds: UnsafeMutablePointer<UnsafeMutablePointer<Int32>?>,
                            _ cnt: UnsafeMutablePointer<Int>) -> Int32

func launchdListenFD() -> Int32? {
    var fds: UnsafeMutablePointer<Int32>? = nil
    var cnt = 0
    let rc = "Listeners".withCString { launch_activate_socket($0, &fds, &cnt) }
    guard rc == 0, let f = fds, cnt > 0 else {
        hlog("Ошибка launch_activate_socket rc=\(rc) cnt=\(cnt)")
        return nil
    }
    return f[0]
}

func peerUID(_ fd: Int32) -> uid_t? {
    var uid: uid_t = 0
    var gid: gid_t = 0
    return getpeereid(fd, &uid, &gid) == 0 ? uid : nil
}

func writeAll(_ fd: Int32, _ data: Data) {
    data.withUnsafeBytes { raw in
        guard let base = raw.baseAddress else { return }
        var off = 0
        while off < data.count {
            let n = write(fd, base.advanced(by: off), data.count - off)
            if n <= 0 { break }
            off += n
        }
    }
}

func respond(_ fd: Int32, _ obj: [String: Any]) {
    var d = obj
    d["v"] = 1
    guard let data = try? JSONSerialization.data(withJSONObject: d, options: [.sortedKeys]) else { return }
    var out = data
    out.append(0x0A)
    writeAll(fd, out)
}

// MARK: - 指令处理（严格白名单）

func handle(line: String, dryRun: Bool) -> [String: Any] {
    guard let data = line.data(using: .utf8),
          let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
          let cmd = obj["cmd"] as? String else {
        return ["ok": false, "msg": "Некорректный JSON или отсутствует cmd"]
    }
    switch cmd {
    case "ping":
        return ["ok": true, "msg": "pong", "version": H.version, "pid": Int(getpid()),
                "zone": readZone(), "auto": readAuto() as Any, "dryRun": dryRun]

    case "state":
        var d: [String: Any] = ["ok": true, "msg": "Текущее состояние", "zone": readZone(),
                                "euid": Int(geteuid())]
        if let a = readAuto() { d["auto"] = a }
        return d

    case "set_zone":
        guard let zone = obj["zone"] as? String else { return ["ok": false, "msg": "Отсутствует поле zone"] }
        let auto = obj["auto"] as? Bool
        let r = applyZone(zone, auto: auto, dryRun: dryRun)
        hlog("set_zone zone=\(zone) auto=\(auto.map(String.init) ?? "-") → ok=\(r.ok) \(r.msg)")
        return r.json

    case "set_auto":
        guard let a = obj["auto"] as? Bool else { return ["ok": false, "msg": "Отсутствует логическое поле auto"] }
        // 复用 applyZone：zone 传当前值，只动 auto
        let cur = readZone()
        guard !cur.isEmpty, zoneFile(cur) != nil else {
            return ["ok": false, "msg": "Текущий пояс \(cur) не разрешён; операция отклонена"]
        }
        let r = applyZone(cur, auto: a, dryRun: dryRun)
        hlog("set_auto auto=\(a) → ok=\(r.ok) \(r.msg)")
        return r.json

    default:
        // 明确不做的事：不接受任意命令、不接受路径、不存在 exec 指令
        return ["ok": false, "msg": "Неподдерживаемая команда: \(cmd) (допустимы ping/state/set_zone/set_auto)"]
    }
}

// MARK: - 连接服务

func serveClient(_ cfd: Int32, allowUID: uid_t, dryRun: Bool) {
    guard let uid = peerUID(cfd) else {
        respond(cfd, ["ok": false, "msg": "Не удалось определить UID клиента"])
        return
    }
    guard uid == allowUID || uid == 0 else {
        hlog("Соединение отклонено: UID клиента=\(uid), разрешён=\(allowUID)")
        respond(cfd, ["ok": false, "msg": "UID клиента \(uid) не авторизован (разрешён \(allowUID))"])
        return
    }
    var buf = Data()
    var chunk = [UInt8](repeating: 0, count: 4096)
    while true {
        let n = read(cfd, &chunk, chunk.count)
        if n <= 0 { break }
        buf.append(contentsOf: chunk[0..<n])
        while let nl = buf.firstIndex(of: 0x0A) {
            let lineData = buf.subdata(in: buf.startIndex..<nl)
            buf.removeSubrange(buf.startIndex...nl)
            guard let line = String(data: lineData, encoding: .utf8) else { continue }
            let s = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if !s.isEmpty { respond(cfd, handle(line: s, dryRun: dryRun)) }
        }
    }
}

/// 服务循环：空闲 idle 秒即退出（不常驻）
func serveLoop(listenFD: Int32, allowUID: uid_t, dryRun: Bool, idle: Int32) {
    let born = Date()
    while Date().timeIntervalSince(born) < H.maxLifeSeconds {
        var pfd = pollfd(fd: listenFD, events: Int16(POLLIN), revents: 0)
        let pr = poll(&pfd, 1, idle * 1000)
        if pr == 0 { hlog("Нет запросов \(idle) с; завершение работы"); break }
        if pr < 0 {
            if errno == EINTR { continue }
            hlog("Ошибка poll errno=\(errno)")
            break
        }
        let cfd = accept(listenFD, nil, nil)
        if cfd < 0 {
            if errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { continue }
            hlog("Ошибка accept errno=\(errno)")
            break
        }
        serveClient(cfd, allowUID: allowUID, dryRun: dryRun)
        close(cfd)
    }
}

// MARK: - 客户端（自测 & 手工调用用；主程序里有独立实现）

func clientRequest(socketPath: String, json: String, timeout: TimeInterval = 5) -> [String: Any]? {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return nil }
    defer { close(fd) }
    var (addr, len) = makeAddr(socketPath)
    let rc = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, len) }
    }
    guard rc == 0 else { return nil }

    var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
    var out = Data(json.utf8)
    out.append(0x0A)
    writeAll(fd, out)

    var buf = Data()
    var chunk = [UInt8](repeating: 0, count: 4096)
    while true {
        let n = read(fd, &chunk, chunk.count)
        if n <= 0 { break }
        buf.append(contentsOf: chunk[0..<n])
        if buf.contains(0x0A) { break }
    }
    guard let nl = buf.firstIndex(of: 0x0A) else { return nil }
    let lineData = buf.subdata(in: buf.startIndex..<nl)
    return (try? JSONSerialization.jsonObject(with: lineData)) as? [String: Any]
}

// MARK: - 自测（无需 root）

func selftest() -> Int32 {
    signal(SIGPIPE, SIG_IGN)
    let path = NSTemporaryDirectory() + "autoz-helper-selftest-\(getpid()).sock"
    try? FileManager.default.removeItem(atPath: path)
    let lfd = bindListen(path)
    guard lfd >= 0 else { print("✗ Не удалось открыть сокет \(path)"); return 1 }

    // 另起一个「只允许别的 uid」的监听，用来验证 uid 门禁
    let path2 = path + ".deny"
    try? FileManager.default.removeItem(atPath: path2)
    let lfd2 = bindListen(path2)
    let denyUID: uid_t = getuid() == 0 ? 501 : getuid() &+ 1

    // 两个监听必须各用一条队列：serveLoop 是阻塞的，共用串行队列会让第二个起不来
    let q1 = DispatchQueue(label: "selftest.serve.1")
    let q2 = DispatchQueue(label: "selftest.serve.2")
    q1.async { serveLoop(listenFD: lfd, allowUID: getuid(), dryRun: true, idle: 8) }
    if lfd2 >= 0 { q2.async { serveLoop(listenFD: lfd2, allowUID: denyUID, dryRun: true, idle: 8) } }
    usleep(200_000)   // 等服务线程进入 accept

    var pass = 0, fail = 0
    func check(_ name: String, _ req: String, socket: String? = nil, _ expect: ([String: Any]) -> Bool) {
        guard let r = clientRequest(socketPath: socket ?? path, json: req) else {
            print("✗ \(name) — нет ответа"); fail += 1; return
        }
        if expect(r) { print("✓ \(name)"); pass += 1 }
        else { print("✗ \(name) — ответ: \(r)"); fail += 1 }
    }

    print("=== Проверка autoz-helper (пробный режим, без изменения системы)===")
    print("socket: \(path)")
    print("Текущий UID: \(getuid())  UID для проверки отказа: \(denyUID)")
    print("")

    check("Успешный ping", #"{"cmd":"ping"}"#) { $0["ok"] as? Bool == true && $0["msg"] as? String == "pong" }
    check("state возвращает текущий пояс", #"{"cmd":"state"}"#) { ($0["zone"] as? String)?.isEmpty == false }
    check("Отклонение обхода пути ../..", #"{"cmd":"set_zone","zone":"../../etc/passwd"}"#) {
        $0["ok"] as? Bool == false
    }
    check("Отклонение абсолютного пути /etc/passwd", #"{"cmd":"set_zone","zone":"/etc/passwd"}"#) {
        $0["ok"] as? Bool == false
    }
    check("Отклонение несуществующего пояса", #"{"cmd":"set_zone","zone":"Nope/Nowhere"}"#) {
        $0["ok"] as? Bool == false
    }
    check("Допустимый пояс принят (план без выполнения)", #"{"cmd":"set_zone","zone":"Asia/Tokyo","auto":false}"#) {
        $0["ok"] as? Bool == true && (($0["steps"] as? [String])?.isEmpty == false)
    }
    check("set_auto с логическим значением", #"{"cmd":"set_auto","auto":true}"#) { $0["ok"] as? Bool == true }
    check("Отклонение неизвестной команды (exec недоступен)", #"{"cmd":"exec","program":"/bin/rm"}"#) {
        $0["ok"] as? Bool == false && (($0["msg"] as? String)?.contains("Неподдерживаемая команда") ?? false)
    }
    check("Отклонение сообщения без JSON", "hello world") { $0["ok"] as? Bool == false }
    if lfd2 >= 0 {
        check("Неавторизованный UID отклонён", #"{"cmd":"ping"}"#, socket: path2) {
            $0["ok"] as? Bool == false && (($0["msg"] as? String)?.contains("не авторизован") ?? false)
        }
    }

    // 分片写入（模拟 TCP 半包）：一条 JSON 拆两次 write
    do {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var (addr, len) = makeAddr(path)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, len) }
        }
        if rc == 0 {
            var tv = timeval(tv_sec: 5, tv_usec: 0)
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            writeAll(fd, Data(#"{"cmd":"pi"#.utf8))
            usleep(120_000)
            writeAll(fd, Data("ng\"}\n".utf8))
            var buf = Data(); var chunk = [UInt8](repeating: 0, count: 4096)
            while true {
                let n = read(fd, &chunk, chunk.count)
                if n <= 0 { break }
                buf.append(contentsOf: chunk[0..<n])
                if buf.contains(0x0A) { break }
            }
            close(fd)
            if let nl = buf.firstIndex(of: 0x0A),
               let o = (try? JSONSerialization.jsonObject(with: buf.subdata(in: buf.startIndex..<nl))) as? [String: Any],
               o["ok"] as? Bool == true {
                print("✓ Сообщение из нескольких фрагментов разобрано"); pass += 1
            } else {
                print("✗ Ошибка разбора фрагментированного сообщения"); fail += 1
            }
        }
    }

    print("")
    print("Результат: \(pass) пройдено / \(fail) ошибок")
    try? FileManager.default.removeItem(atPath: path)
    try? FileManager.default.removeItem(atPath: path2)
    return fail == 0 ? 0 : 1
}

// MARK: - 打印计划（不执行）

func printPlan(_ zone: String, auto: Bool?) {
    let cur = readZone()
    print("Версия помощника:   \(H.version)")
    print("socket:        \(H.socketPath)")
    print("Разрешённый UID:      (записывается в plist при установке)")
    print("Текущий EUID:     \(geteuid())")
    print("Текущий пояс:      \(cur.isEmpty ? "неизвестно" : cur)")
    print("Автовыбор пояса:    \(String(describing: readAuto()))")
    print("")
    print("Целевой пояс:      \(zone)")
    if let zf = zoneFile(zone) {
        print("Список разрешённых:    ✓ допустим (\(zf))")
    } else {
        print("Список разрешённых:    ✗ отклонён (недопустим или отсутствует); действий не будет")
        return
    }
    print("Автовыбор пояса:  \(auto.map { $0 ? "вкл." : "выкл." } ?? "без изменения")")
    print("")
    print("План (прямые аргументы argv, без оболочки):")
    let r = applyZone(zone, auto: auto, dryRun: true)
    if r.steps.isEmpty { print("  (изменений не требуется, целевое состояние уже установлено)") }
    for (i, s) in r.steps.enumerated() { print("  \(i + 1). \(s)") }
}

// MARK: - 入口

let args = Array(CommandLine.arguments.dropFirst())
signal(SIGPIPE, SIG_IGN)

func intArg(_ name: String, _ def: Int) -> Int {
    guard let i = args.firstIndex(of: name), i + 1 < args.count, let v = Int(args[i + 1]) else { return def }
    return v
}
func strArg(_ name: String) -> String? {
    guard let i = args.firstIndex(of: name), i + 1 < args.count else { return nil }
    return args[i + 1]
}
func has(_ flag: String) -> Bool { args.contains(flag) }

if has("--version") {
    print("autoz-helper \(H.version)")
    exit(0)
}

// 注意：无参数时**不能**当 help —— launchd 可能以无参形式拉起，此时必须进入服务模式
if has("--help") {
    print("""
    autoz-helper \(H.version) — Помощник AutoZ с правами администратора

    Режим launchd (по умолчанию, запуск по запросу через Sockets):
      autoz-helper --allow-uid <uid>

    Ручной запуск сокета (отладка, без root):
      autoz-helper --socket <path> --allow-uid <uid> [--dry-run]

    Проверки (без root и изменения системы):
      autoz-helper --selftest

    Просмотр (без выполнения):
      autoz-helper --state
      autoz-helper --print-plan <zone> [--auto true|false]

    Однократное выполнение (нужен root):
      sudo autoz-helper --set-zone <zone> [--auto true|false] [--dry-run]

    Команды (сокет, JSON с разделением строк):
      {"cmd":"ping"}
      {"cmd":"state"}
      {"cmd":"set_zone","zone":"Asia/Tokyo","auto":false}
      {"cmd":"set_auto","auto":true}
    """)
    exit(0)
}

let allowUID = uid_t(intArg("--allow-uid", 0))
let dryRun = has("--dry-run")

if has("--selftest") {
    exit(selftest())
}

if has("--state") {
    print("Пояс:       \(readZone())")
    print("Автовыбор пояса: \(String(describing: readAuto()))")
    print("euid:       \(geteuid())")
    print("socket:     \(FileManager.default.fileExists(atPath: H.socketPath) ? "есть" : "нет")")
    print("plist:      \(FileManager.default.fileExists(atPath: H.plistPath) ? "есть" : "нет")")
    exit(0)
}

if has("--print-plan") {
    let zone = strArg("--print-plan") ?? readZone()
    var auto: Bool? = nil
    if let a = strArg("--auto") { auto = (a == "true" || a == "1") }
    printPlan(zone, auto: auto)
    exit(0)
}

if has("--set-zone") {
    guard let zone = strArg("--set-zone") else {
        print("Использование: --set-zone <пояс IANA>"); exit(1)
    }
    var auto: Bool? = nil
    if let a = strArg("--auto") { auto = (a == "true" || a == "1") }
    if !dryRun && geteuid() != 0 {
        print("✗ Нужен root (текущий EUID=\(geteuid())). Используйте sudo или просмотрите план с --dry-run.")
        exit(2)
    }
    let r = applyZone(zone, auto: auto, dryRun: dryRun)
    print(r.ok ? "OK: \(r.msg) (zone=\(r.zone) auto=\(r.auto.map(String.init) ?? "-"))" : "FAILED: \(r.msg)")
    for s in r.steps { print("  · \(s)") }
    exit(r.ok ? 0 : 3)
}

// ---- 服务模式 ----

var listenFD: Int32 = -1
var cleanupSocket = false

if let p = strArg("--socket") {
    try? FileManager.default.removeItem(atPath: p)
    listenFD = bindListen(p)
    cleanupSocket = true
    hlog("Ручной сокет \(p) allowUID=\(allowUID) dryRun=\(dryRun)")
} else {
    if let fd = launchdListenFD() {
        listenFD = fd
        hlog("Запуск через launchd, получен FD сокета=\(fd) allowUID=\(allowUID)")
    } else {
        // 兜底：launchd 没给 fd（例如被手工以 root 运行），自己监听
        try? FileManager.default.removeItem(atPath: H.socketPath)
        listenFD = bindListen(H.socketPath)
        cleanupSocket = true
        hlog("Нет FD от launchd → отдельный сокет \(H.socketPath)")
    }
}

guard listenFD >= 0 else {
    print("✗ Не удалось открыть сокет")
    exit(1)
}

serveLoop(listenFD: listenFD, allowUID: allowUID, dryRun: dryRun, idle: H.idleSeconds)
if cleanupSocket { try? FileManager.default.removeItem(atPath: H.socketPath) }
exit(0)

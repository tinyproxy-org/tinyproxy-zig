# Tinyproxy C 版产品技术文档

本文基于 `../tinyproxy/src/`、`../tinyproxy/docs/man5/tinyproxy.conf.txt`、`../tinyproxy/docs/man8/tinyproxy.txt`、`../tinyproxy/etc/tinyproxy.conf` 和官方测试脚本反推。本文是源码级静态分析结果，用作 `tinyproxy-zig` 进行 1:1 行为复刻时的产品与技术基线。

## 1. 产品定位

Tinyproxy 是轻量级 HTTP/SSL 代理守护进程，目标是在小型网络、嵌入式或资源受限环境中提供完整但低成本的 HTTP 正向代理能力。

核心能力包括：

- HTTP 正向代理：处理显式代理请求，例如 `GET http://host/path HTTP/1.1`。
- HTTPS 隧道代理：通过 `CONNECT host:port HTTP/1.1` 建立 TCP 隧道。
- 访问控制：按客户端 IP、CIDR、域名后缀允许或拒绝。
- Basic 代理认证。
- Header 匿名化、Header 注入、`Via` 处理。
- 域名或 URL 过滤。
- 上游代理转发：HTTP、SOCKS4、SOCKS5、直连例外。
- 反向代理映射。
- 透明代理支持。
- 内置错误页、统计页、日志、pidfile、配置热重载。

部分能力受编译开关控制；默认 `configure.ac` 中 `xtinyproxy`、`filter`、`upstream`、`reverse`、`transparent` 都是 enabled by default。

## 2. 运行模型

Tinyproxy C 版是多线程阻塞/非阻塞混合模型：

- 主线程创建监听 socket，使用 `poll` 或 `select` 等待新连接。
- 每个客户端连接创建一个 `pthread`。
- `MaxClients` 是并发连接硬上限，默认 `100`。
- 每个线程栈大小尝试设置为 `256 KiB`。
- 请求解析、认证、建立上游连接阶段主要使用阻塞 socket。
- 进入双向转发后使用 `poll` 或 `select` 和内部 buffer 做非阻塞 relay。
- 每方向 buffer 上限来自 `MAXBUFFSIZE = 96 KiB`。
- 单行读取上限为 `128 KiB`。
- header 读取循环最多 `10000` 行，但实际 header map 最多保存 `256` 项。

`Timeout` 控制 socket 收发超时和 relay idle timeout，默认 `600` 秒。设置为 `0` 会回退到默认值。

## 3. 启动与进程行为

命令行参数：

- `-c FILE`：指定配置文件。
- `-d`：前台运行，不 daemonize。
- `-h`：输出帮助。
- `-v`：输出版本。

启动流程：

1. 初始化配置解析器。
2. 读取配置文件，`Port` 必填。
3. 初始化统计。
4. 如开启 Anonymous，自动允许 `Content-Length` 和 `Content-Type`。
5. daemon 模式下 fork 到后台。
6. 初始化过滤器。
7. 创建监听 socket。
8. 创建 pidfile。
9. 如果当前 euid 是 root，按 `Group`、`User` 降权，并清空 supplementary groups。
10. 初始化日志。
11. 注册信号。
12. 进入 accept 主循环。

信号语义：

- `SIGTERM` / `SIGINT`：设置退出标记，主循环退出，关闭监听 socket，尝试结束子线程。
- `SIGHUP`：daemon 模式下触发配置和日志重载，并重载 filter。
- `SIGUSR1`：前台或后台都可触发配置和 filter 重载。
- `SIGPIPE`：忽略。
- `SIGCHLD`：回收子进程，虽然当前模型主要是线程。

## 4. 配置文件语法

配置是逐行 key-value：

- 指令名大小写不敏感。
- 值大小写敏感。
- 空行和首字符为 `#` 的行被忽略。
- 字符串参数通常必须用双引号。
- 布尔值只接受 `yes|on|no|off`，大小写不敏感。
- 语法错误会导致启动或 reload 失败。

重要默认值：

- `Port`：无默认，必填。
- `MaxClients`：`100`。
- `Timeout`：`600`。
- `StatHost`：默认编译值，一般是 `tinyproxy.stats`。
- `BasicAuthRealm`：默认 `PACKAGE_NAME`，即 Tinyproxy。
- `LogFile`：默认空；前台时可输出到 stdout，daemon 且未配置日志会警告 logging deactivated。
- ACL：没有任何 `Allow`/`Deny` 时默认允许所有客户端；只要存在 ACL，默认拒绝。

## 5. 请求生命周期

单连接主流程：

1. 记录客户端 IP。
2. 如果 `BindSame` 开启，记录本地入站 socket IP，用于出站 bind。
3. 检查代理 loop 防护。
4. 检查 ACL。
5. 读取 request line，跳过空行。
6. 读取所有客户端 header，支持 folded header。
7. 如果配置了 `BasicAuth`，验证认证。
8. 应用 `AddHeader` 到内部 header map。
9. 解析请求目标：
   - `http://...`：普通 HTTP 正向代理。
   - `ftp://...`：仅在 upstream 配置存在时作为 upstream HTTP 请求路径处理。
   - `CONNECT host:port`：隧道代理。
   - 其他形式：如果编译了 transparent proxy，则尝试透明代理解析；否则返回 `501`。
10. 执行 filter。
11. 如果 host 等于 `StatHost`，返回内置统计页。
12. 按 upstream 规则选择上游代理或直连。
13. 对 HTTP 请求发送新 request line、Host、Connection、Via 等 header。
14. 对 CONNECT：
    - 直连或 SOCKS 上游成功后，返回 `HTTP/1.x 200 Connection established`。
    - HTTP upstream 下，把 CONNECT 转发给上游并处理上游响应。
15. 进入 relay，直到 EOF、错误、server content-length 读完或 idle timeout。

## 6. HTTP 请求解析语义

支持两种 request line：

- `GET url`：视为 HTTP/0.9。
- `METHOD url HTTP/x.y`：解析协议版本。

错误行为：

- request line 格式非法：`400 Bad Request`。
- URL 无法解析：`400 Bad Request`。
- CONNECT 端口不允许：`403 Access violation`。
- filter 命中阻断：`403 Filtered`。
- 未知方法或协议：`501 Not Implemented`。
- 连接目标失败：直连失败是 `500 Unable to connect`；upstream 失败是 `502 Unable to connect to upstream proxy`。
- 远端 header 读取失败：`503 Could not retrieve all the headers`。

URL 解析细节：

- 会移除 `user:pass@host` 中的用户密码部分。
- `host:port` 中端口会覆盖默认端口。
- IPv6 literal 会去掉外层 `[]` 存储；转发 `Host` 时再加回 `[]`。
- HTTP 默认端口 80，CONNECT 默认端口 443。
- 如果没有 path，默认 `/`。

## 7. Header 行为

发往上游服务端时：

- Tinyproxy 自己生成 request line。
- 强制发送 `Connection: close`。
- 重新发送 `Host`。
- 移除这些客户端 header：
  - `host`
  - `keep-alive`
  - `proxy-connection`
  - `te`
  - `trailers`
  - `upgrade`
- 读取 `Connection` 和 `Proxy-Connection` 中列出的 hop-by-hop header，并从 header map 中移除。
- 默认添加或追加 `Via`。
- 如果 `DisableViaHeader Yes`，不发送 `Via`，但这违反 HTTP 代理规范。
- 如果 `ViaProxyName` 配置存在，用它替代本机 hostname。
- 如果 `XTinyproxy Yes` 且编译支持，添加 `X-Tinyproxy: <client-ip>`。
- 如果 `Anonymous` 启用，只转发 allowlist 中的 header。

发回客户端时：

- 保留远端 response line。
- 移除：
  - `keep-alive`
  - `proxy-authenticate`
  - `proxy-authorization`
  - `proxy-connection`
- 同样处理 `Connection` 和 `Proxy-Connection` 引用的 hop-by-hop header。
- 添加或追加 `Via`。
- 反向代理模式下可追加 tracking cookie 或重写 `Location`。

## 8. CONNECT 行为

`ConnectPort` 控制允许的 CONNECT 目标端口：

- 没有任何 `ConnectPort`：允许所有端口。
- 配置了若干端口：只允许这些端口。
- 只配置 `ConnectPort 0`：实际效果是禁止所有正常端口 CONNECT。

CONNECT 成功响应格式：

```http
HTTP/1.x 200 Connection established
Proxy-agent: tinyproxy
```

随后进入透明 TCP relay，不再解析 TLS 内容。

## 9. ACL 访问控制

`Allow` / `Deny` 可多次出现，按配置顺序检查：

- 无 ACL：允许所有客户端。
- 有 ACL：默认拒绝。
- 数字地址支持 IPv4、IPv6、CIDR、IPv4 dotted netmask。
- 字符串规则可匹配客户端反向解析 hostname 的后缀。
- 如果字符串规则不以 `.` 开头，还会先尝试把该 hostname 正向解析成 IP，与客户端 IP 比较。
- 第一个明确匹配的 deny 会拒绝；第一个明确匹配的 allow 会允许；无匹配最终拒绝。

域名 ACL 可能导致每个新连接做 DNS 解析，存在性能成本。

## 10. BasicAuth

配置任意 `BasicAuth user password` 后，代理要求认证：

- 普通代理请求使用 `Proxy-Authorization: Basic ...`。
- 如果请求 `StatHost` 且没有 `Proxy-Authorization`，会尝试用普通 `Authorization`，失败时返回 `401`。
- 其他代理认证失败返回 `407 Proxy Authentication Required`。
- `407` 响应带 `Proxy-Authenticate: Basic realm="..."`。
- `401` 响应带 `WWW-Authenticate: Basic realm="..."`。
- `BasicAuthRealm` 可配置 realm。
- 用户密码编码后与配置列表中的 base64 字符串精确比较。

## 11. 过滤功能

需要编译 `FILTER_ENABLE`。

配置：

- `Filter "path"`：过滤规则文件。
- `FilterType bre|ere|fnmatch`：匹配类型。
- `FilterURLs On`：按完整 URL 过滤；默认按 host/domain 过滤。
- `FilterCaseSensitive On`：正则大小写敏感；默认正则不敏感。`fnmatch` 始终大小写敏感。
- `FilterDefaultDeny Yes`：白名单模式；默认是黑名单模式。
- `FilterExtended` 已废弃，等价于使用 ERE。

规则文件：

- 每行一条规则。
- 跳过前导空白。
- 空白后内容被截断。
- `#` 开始注释，除非前一个字符是反斜杠。
- BRE/ERE 会编译 regex；fnmatch 保存 pattern。

判定：

- 默认 allow 模式：任一规则匹配则拒绝，否则允许。
- default-deny 模式：任一规则匹配则允许，否则拒绝。

## 12. Upstream 上游代理

需要编译 `UPSTREAM_SUPPORT`。

支持类型：

- `http`
- `socks4`
- `socks5`
- `none`

语法：

```conf
Upstream http host:port
Upstream http user:pass@host:port ".example.com"
Upstream socks4 host:port
Upstream socks5 user:pass@host:port "10.0.0.0/8"
Upstream none ".internal.example.com"
```

匹配规则：

- 规则保存在链表中。
- 目标规则插入到链表头，default upstream 放到链表尾。
- 因为配置越靠后的目标规则越晚插入链表头，所以“最后匹配的规则生效”。
- default upstream 只能有一个。
- `none` 规则表示匹配目标直连，不使用上游。
- hostspec 支持精确域名、以 `.` 开头的后缀、IP/mask。

HTTP upstream：

- 普通 HTTP 请求会把 path 改成 absolute-form：`http://host:port/path`。
- CONNECT 会把 path 改成 `host:port`。
- 如果 upstream 配置了 user/pass，会发送 `Proxy-Authorization: Basic ...` 给 upstream。

SOCKS4：

- 使用 SOCKS4a 形式，目标 IP 固定 fake `0.0.0.1`，真实 host 放在 domain 字段。
- 不使用用户名，发送空 user。
- host 长度超过 255 失败。

SOCKS5：

- 支持 no-auth 和 username/password auth。
- CONNECT 命令使用 domainname address type。
- host 长度超过 255 失败。

## 13. 反向代理

需要编译 `REVERSE_SUPPORT`。

配置：

```conf
ReversePath "/local/" "http://backend/"
ReverseOnly Yes
ReverseMagic Yes
ReverseBaseURL "http://public-proxy/"
```

行为：

- `ReversePath` 的 path 必须以 `/` 开头；如果不以 `/` 结尾，内部补 `/`。
- URL 必须包含 `://`。
- 如果只给一个字符串参数，则等价于 path `/` 映射到该 URL。
- 请求 URL 以 `/` 开头时才参与 reverse rewrite。
- 匹配 path 后，把本地 path 前缀替换成远端 URL。
- 如果请求 `/foo` 命中配置 `/foo/`，会返回 `301 Moved Permanently` 到补斜杠路径。
- `ReverseOnly Yes` 下，没有 reverse mapping 的请求返回 `400 Bad Request`。
- `ReverseMagic Yes` 使用 cookie `yummy_magical_cookie` 跟踪 reverse path，让绝对链接场景继续映射。
- 响应时如果设置了 `ReverseBaseURL`，并且 `Location` 以某个 reverse 后端 URL 开头，会重写成 public base URL + local path。

## 14. 透明代理

需要编译 `TRANSPARENT_PROXY`。

透明代理无需专门配置项。当前端防火墙把 HTTP 流量重定向到 Tinyproxy 时：

- 如果请求带 `Host` header，使用 Host 作为目标 host/port，默认端口 80。
- 如果没有 `Host`，通过 `getsockname()` 获取原始目的地址和端口。
- 构造内部 URL：`http://host:port/path`。
- 如果目标 host 等于本地 `Listen` 地址，返回 `400 Bad Request` 防止连到自己。

透明代理只适合 HTTP；HTTPS 透明拦截不等同于 CONNECT 代理。

## 15. Anonymous 匿名代理

配置任意 `Anonymous "Header"` 后启用匿名模式：

- 只有列出的 header 会被转发。
- 未配置 Anonymous 时，默认转发所有未被 Tinyproxy 删除的 header。
- 启动时如果匿名模式启用，会自动加入 `Content-Length` 和 `Content-Type`，因为 HTTP/1.0 请求体需要它们。
- Cookie、Authorization 等如果未显式允许，会被剥离。

## 16. AddHeader

`AddHeader "Name" "Value"` 会把 header 加入 outgoing HTTP request 的内部 header map。

限制：

- 只影响 Tinyproxy 能控制的 HTTP 请求。
- 不影响直连 CONNECT 后的 HTTPS 内容。
- 如果 header name 与已有 header 重复，内部 map 允许重复项；后续某些 remove 操作会按 key 删除所有匹配项。

## 17. 统计页

`StatHost` 命中的请求不会转发到远端，而是返回内部统计页。

统计项：

- open connections
- total requests
- bad connections
- denied connections
- refused connections due to high load

源码中 `STAT_REFUSE` 有统计字段，但当前 `MaxClients` 满时只拒绝 accept 新连接并记录日志，没有看到调用 `update_stats(STAT_REFUSE)` 的路径，因此该计数可能不会随满载拒绝增长。

`StatFile` 可配置模板；否则返回硬编码 XHTML 页面。

## 18. 错误页与模板变量

错误页配置：

```conf
ErrorFile 403 "/path/403.html"
DefaultErrorFile "/path/default.html"
```

响应 header：

- `HTTP/1.x <code> <message>`
- `Server: tinyproxy`
- `Content-Type: text/html`
- `Connection: close`
- 认证错误额外带认证 challenge header。

模板变量包括：

- `{errno}`
- `{cause}`
- `{request}`
- `{clientip}`
- `{date}`
- `{website}`
- `{version}`
- `{package}`
- `{detail}`
- stats 模板还包括 `{opens}`、`{reqs}`、`{badconns}`、`{deniedconns}`、`{refusedconns}`。

如果指定错误文件打不开，会返回内置 fallback XHTML。

## 19. 日志

支持：

- `LogFile "path"`
- `Syslog On`
- `LogLevel critical|error|warning|notice|connect|info`

行为：

- `LogFile` 和 `Syslog` 文档上互斥；源码里若 `Syslog On`，优先 syslog。
- 未初始化日志前的日志会暂存，初始化后补发。
- 文件日志使用安全创建逻辑，避免 symlink/link race。
- 文件日志每条写完后 `fsync`。
- 文件写失败时切换到 syslog。
- `LogLevel Connect` 表示记录连接事件但过滤 `Info` 噪音。

## 20. 网络与资源行为

监听：

- 没有 `Listen` 时，对 wildcard 地址监听，可能同时监听 IPv4/IPv6。
- IPv6 listener 设置 `IPV6_V6ONLY`。
- listener 设置 `SO_REUSEADDR`。
- 有多个 `Listen` 时，逐个创建监听 socket。

出站：

- `Bind` 可配置多个出站 bind 地址，按顺序尝试。
- `BindSame Yes` 优先把出站连接 bind 到接收入站连接的本地 IP。
- 出站连接使用 `getaddrinfo`，逐个地址尝试。
- 连接到等于本代理端口的目标时，会记录 loop record；短时间内收到对应入站连接会判定代理循环并返回 400。

Relay：

- 双向 buffer 队列按读写事件驱动。
- 如果 server response 有 `Content-Length`，relay 会在读满该长度后停止。
- client/server 空闲超过 `Timeout` 关闭。
- relay 结束后会尽量 flush server-to-client buffer，shutdown client write side，再阻塞 flush client-to-server buffer。

## 21. 已知边界与约束

- 这是 HTTP/1.x 风格代理，不是 HTTP/2 或 HTTP/3 代理。
- HTTPS 内容只在 CONNECT 隧道中透传，不解析、不改 header、不过滤 URL path。
- `FilterURLs` 对 HTTPS 基本无效，因为 CONNECT 后看不到 URL。
- `Anonymous`、`AddHeader`、`Via` 主要影响普通 HTTP 请求，不影响 CONNECT 隧道内流量。
- `Via` 可关闭，但会破坏 HTTP 代理规范合规性。
- 域名 ACL 会引入 DNS 解析开销。
- BasicAuth 是明文配置 + Basic 认证语义，应配合受信网络或外层 TLS/隧道使用。
- `MaxClients` 满时主循环不 accept 新连接，而是短 sleep 后重试；客户端侧可能表现为连接排队或超时。
- 配置 reload 会替换全局配置并重载 filter；已有连接使用全局 `config` 指针读取某些运行期值，严格的 per-connection 配置快照语义并不存在。

## 22. 证据摘要

主要依据文件：

- `../tinyproxy/src/main.c`：启动、信号、reload、降权。
- `../tinyproxy/src/conf.c` / `../tinyproxy/src/conf.h`：配置语法、默认值、指令集合。
- `../tinyproxy/src/child.c`：accept loop、线程模型、`MaxClients`。
- `../tinyproxy/src/reqs.c`：请求解析、认证、CONNECT、header 处理、upstream、relay。
- `../tinyproxy/src/acl.c` / `../tinyproxy/src/hostspec.c`：ACL 和 hostspec 匹配。
- `../tinyproxy/src/filter.c`：过滤规则加载与匹配。
- `../tinyproxy/src/upstream.c`：上游代理规则和匹配。
- `../tinyproxy/src/reverse-proxy.c`：反向代理 rewrite。
- `../tinyproxy/src/html-error.c` / `../tinyproxy/src/stats.c`：错误页、模板变量、统计页。
- `../tinyproxy/docs/man5/tinyproxy.conf.txt`、`../tinyproxy/etc/tinyproxy.conf`：对外配置说明。
- `../tinyproxy/tests/scripts/run_tests.sh`：官方行为测试覆盖点。

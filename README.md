# Kaivo 微服务运行库

`github.com/Kaivodev/servicekit` 提供各私有服务共用的运行基础，采用官方 grpc-go。业务处理、用户认证、RBAC、资金模型、业务表结构与迁移仍由服务仓库维护；签名事件与已用认证证明的辅助只操作服务传入的表。

- `config`：集中校验 `AIPAY_*` 配置；服务端必须提供 PostgreSQL、传输身份配置和明确的调用方名单。缓存 Redis 可选。在 `production` 环境中，缓存 Redis 和队列 Redis 的连接地址都必须使用 `rediss://`。`AIPAY_ENVIRONMENT` 由 `config.ParseEnvironment` 统一解析，只取 `development`、`test` 或 `production`，未设置按 `production` 处理，其他值（含已移除的 `staging`）启动失败。放宽开关分两档：`IsDevelopment()` 只在 `development` 下成立，`IsDevelopmentOrTest()` 在 `development` 和 `test` 下成立。
- `mtls` / `rpc`：TLS 1.3、双向证书链校验、DNS 校验与 `spiffe://<trust-domain>/service/<name>` 身份绑定；连接复用、unary 超时、调用取消、报文大小限制、关联 ID 和访问日志。
- `postgres` / `redis`：连接池和有界关闭；schema 版本、dirty 标记和服务属主校验。
- `migration`：显式执行服务自身内嵌迁移；数据库级锁串行验证属主与执行迁移，拒绝跨服务和无属主的既有迁移历史。
- `queue`：专用 Redis 的显式 Asynq producer/worker、重试策略、就绪和有界排空；handler 与 outbox 由业务属主提供。
- `cli`：`serve`、`version`、`healthcheck`、`migrate up|down|version`。`down` 只回滚最近一次迁移，可能删除数据。
- `authz`：服务端方法级授权。`LoadPolicies(eventsv1.File_….Services().ByName(…), …)` 从生成 SDK 的服务描述读取 `(aipay.authz.v1.policy)`，任何方法缺少合法策略即启动失败；拦截器按传输层验证的服务身份匹配调用方规则，按要求核验 IAM 认证证明（紧凑 JWS ES256、`kid` 查本服务配置的 JWKS 公钥登记表、签发方、60 秒有效期、受众、权限、`amr` 含 `mfa` 与 `auth_time` 时限），单次使用的方法在调用业务前经 `ReplayGuard` 记录 `jti`（提供 PostgreSQL 实现）。`acting_scope` 按账户模型严格解析（`platform`、`account`、`business`、`application`；缺少所需 ID、类型未知、个人账户带组织 ID、出现其他成员或商户应用不在应用范围时一律拒绝）。核验结果以只读 `authz.Call` 交给业务：`Account()` 给出可信的资金账户，`RequireScope(authz.ScopeAccount)` 用于余额、地址簿、提现等账户级资金方法，业务或应用范围的角色因此不能借同一账户取得资金权限。原始证明从 metadata 中移除；拒绝只记录稳定原因，不记录证明内容。`rpc.ServerOptions.Authorizer` 为空时，除健康检查外的方法一律拒绝。
- `signing`：业务签名器（ECDSA P-256、SHA-256、DER）。生产使用 `KMSKey` 适配的不可导出密钥，签名后本地复核；内存签名器只能经 `signing.Open` 在 `AIPAY_ENVIRONMENT=development` 下取得，未设置环境即按生产拒绝。`PublicKeys` 读取 JWKS，拒绝含私钥成员的文件。
- `eventstream`：签名事件。产生端排序器在一个事务内锁流头、按 outbox 顺序分配连续序号、串接 `prev_digest`、签名并一次写入；`Reader` 按流清单限定接收方提供 `ListEvents`/`GetStreamHead`；接收端 `Puller` 校验序号、链、载荷摘要、签名与已知类型，校验通过的信封与游标同事务写入 inbox，任何失败都保存已验证前缀并把流置为停止，`CheckHead` 发现产生方历史回退或分叉同样停止；`Inbox` 在业务事务中一次性记录处理结果。表名由服务提供，列遵循数据库设计的共用模板。
- `marketdata`：行情采集（A134）。按域调度 OKX、Binance、Coinbase、Kraken 四个公开来源，以及前 20 条挂单的筛选、精确中位数、最少样本、同分钟重试、原始响应摘要和指标。CNY/USDT 每分钟一次，USDT/USD 每 5 分钟一次。本包不访问数据库，结果交给服务实现的 `Sink`，由服务写入本域行情表；报价、放币和汇率登记的判断也由服务负责。
- `egressproxy`、`cmd/egress-proxy`：每个命名空间一个出站代理。只接受到白名单主机 443 端口的 CONNECT，只解析 IPv4；解析结果里有私网、回环、链路本地或保留地址时拒绝连接，并直接连接已检查的 IP。不解密 TLS，只输出 JSON 连接日志。`AIPAY_EGRESS_PROXY_TEST_ONLY_ALLOW_CIDRS` 只在 `development` 下有效。
- `approval`：审批摘要 `SHA-256("AIPAY-APPROVAL-V1" || 规范请求)` 与 WebAuthn 断言校验（`webauthn.get`、`challenge`、来源、RP ID、UP/UV 标志、签名计数、COSE ES256 公钥、过期、自批与重复审批人）。签名计数恒为 0 的同步型 passkey 在已记录计数也为 0 时接受；计数一旦不为 0 就必须严格递增，回到 0 视为回退。

契约来自固定版本的 `github.com/Kaivodev/protobuf`：方法策略直接读取生成的 `aipay.authz.v1` 选项类型，新版本契约里本库尚不执行的策略字段会让加载失败；事件信封就是 `aipay.events.v1.SignedEvent`，`eventstream.Reader` 直接实现 `EventStreamServiceServer`（调用方取自授权上下文），`Puller` 直接使用生成的客户端；审批断言为 `aipay.approval.v1.WebAuthnAssertion`。签名事件与审批的测试使用 SDK 的 `testvectors`。`authz/authztest` 只为本库测试构造带策略的测试服务。

自 `v0.6.0` 起，`authz.Claims` 支持 `CommandSHA256`、`SessionID`、`WebEntry`，已验签的 `Assertion` 通过同名只读方法返回。命令摘要为 64 位小写十六进制 SHA-256，会话 ID 为规范小写 UUIDv7，入口使用 `authz.WebEntryPlatformAdmin` / `authz.WebEntryUpstreamPortal`；旧证明可省略，访问器返回空值。签发与接收均检查格式，显式空值、null、错误类型或未知入口拒绝，不把未知入口默认为管理端。

这些声明不自动开放业务：属主须按方法要求其存在，重算完整命令摘要并核对入口、认证方式、作用域与资源归属；`RequestFingerprint()` 不能代替命令摘要。公共库不读取会话数据库、不提供即时撤销、不编码 collection 请求，也不更改 MFA_RECENT/SINGLE_USE 策略。本地签发及真实 mTLS 测试只验证公共库，不代表平台登录或 collection 业务接通。

组装根显式构造资源并注册业务 RPC；框架不自动发现业务。当前各私有服务仅注册标准 gRPC Health，空服务名表示进程及依赖就绪；不存在的业务服务返回 `NOT_FOUND`，不会报告业务可用。调用方身份仅证明服务身份，不能替代用户权限或资源范围检查。

就绪检查覆盖数据库连接、schema 和已配置的 Redis。SIGINT/SIGTERM 后先标记不就绪，再排空 RPC，最后关闭连接池；到期强制退出并返回失败。unary 默认 5 秒、报文默认 1 MiB、停机默认 15 秒。流式 RPC 由调用者控制总时长，业务流必须传递并响应 context；健康 Watch 允许长期保持。客户端不配置应用层自动重试，业务重试必须结合幂等设计。

## 传输与调用方身份

本机与 Compose 默认使用 TLS 1.3 双向认证。K8s 显式选择明文 gRPC，每个 Pod 使用同名 ServiceAccount，分别为每个调用目标投射一个令牌文件，设置 `audience: kaivo:<目标服务>`、`expirationSeconds: 600`。配置约定见[架构决策 A129](https://github.com/Kaivodev/docs/blob/main/plan/decisions.md)。

| 配置键 | 用法 |
| --- | --- |
| `AIPAY_RPC_TRANSPORT` | 默认 `mtls`，K8s 设为 `plaintext` |
| `AIPAY_TLS_CA_FILE`、`AIPAY_TLS_CERT_FILE`、`AIPAY_TLS_KEY_FILE` | mTLS 必填，校验证书链、目标主机名与 SPIFFE 服务身份 |
| `AIPAY_RPC_TOKEN_DIR` | 明文业务进程必填。调用目标 X 时从此目录读取文件 X |
| `AIPAY_RPC_TOKEN_JWKS_FILE` | 明文服务端必填。挂载集群 ServiceAccount 签发方的公钥集 |
| `AIPAY_RPC_TOKEN_ISSUER` | 明文服务端必填，必须与令牌的 `iss` 完全相同 |
| `AIPAY_RPC_SERVICE_NAMESPACES` | 明文业务进程必填，例如 `iam=kaivo-business,ledger=kaivo-ledger`。键为服务名，与 SA 名相同 |

混用 mTLS 身份材料与令牌配置会导致启动失败。组装根调用 `rpc.LoadTransport(cfg, service)`，将返回的传输对象交给 `rpc.NewServer`、`rpc.Connect` 和 `authz.Options.Peer`。仅发起调用的进程可用 `rpc.LoadClientTransport(service, os.Getenv)`，只需客户端侧配置。将 `transport.Check` 加入就绪检查，并随进程启动 `transport.Watch(ctx, cfg.TLS.ReloadInterval, log)`。明文服务端检查令牌目录可读和 JWKS 可用，轮换失败时保留上一次有效公钥并报告未就绪。

每次 unary 调用或创建 stream 时，客户端按文件的修改时间、大小及文件身份复用缓存。文件缺失或为空会终止本次调用。服务端在方法授权前验证 `x-kaivo-service-token`，只接受按 `kid` 选取公钥的三段式 RS256 或 ES256 签名。除签发方外，还要核对以下声明。

- `aud` 为字符串或字符串数组，须包含精确的 `kaivo:<本服务>`。
- `exp`、`nbf`、`iat` 均必填，允许 30 秒时钟偏差。
- `sub` 必须为 `system:serviceaccount:<命名空间>:<服务名>`。如果有 `kubernetes.io` 声明，其中的 `namespace` 和 `serviceaccount.name` 必须与主题一致。命名空间必须与该服务登记的值相同。

验证成功后移除令牌 metadata。监听器检查 `AIPAY_RPC_ALLOWED_PEERS`，随后 protobuf 方法策略、IAM 证明和事件流接收方 ACL 使用同一个已验证的服务名。明文模式的 `grpc.health.v1.Health` 免令牌，kubelet 的原生 gRPC 探针可直接访问服务端口。空服务名报告就绪状态，`healthcheck` 子命令走同一路径。

明文网络上的业务数据、IAM 证明和服务令牌都可被抓包。持有令牌的人可在其有效窗口内向同一目标重放。部署应按调用关系设置 NetworkPolicy，使用短期、限定受众的令牌并收紧节点访问权限。

## 使用与验证

Native mTLS, Compose and the Kubernetes gateway overlay use Rust ABI v3 plugins for trade and verification. Kubernetes selects gateway mode from the payment and reconciliation ConfigMaps. Embedded deployments use the Go plugins. [Kubernetes setup](dev/README.md#kubernetes-gateway-overlay) · [Demo prerequisites](dev/demo.md)

生产使用已发布固定版本，各服务示例配置位于自身 `.env.example`。CI 的只读 `AIPAY_MODULES_TOKEN` 需要读取 observability、protobuf 和 dev/tools 固定使用的已发布 servicekit。本机也可使用 Git 凭据。

```sh
make fmt check build
# 仅对隔离的测试实例执行
AIPAY_TEST_DATABASE_URL=... AIPAY_TEST_REDIS_URL=... make test-integration
# 同级工作区五服务的完整进程验证；只创建并销毁自己的临时数据库实例
python3 script/test-workspace.py --workspace .. --postgres-bin /path/to/postgresql/bin
```

真实 TCP 测试覆盖 TLS、服务名单、错误 CA/主机名、无客户端证书、明文拒绝、关联 ID、健康 Watch、依赖故障、消息限制、取消、正常排空及超时退出。存储测试覆盖迁移锁、属主、回滚、dirty/schema 版本和关闭期限。工作区脚本另外启动五个真实服务，检查错误配置、依赖中断、恢复、日志和 SIGTERM。

开发证书仅用于本机，默认 7 天；输出目录必须不存在，证书和私钥权限为 0600：

```sh
mkdir -p ../.local
go run ./cmd/devcert --out ../.local/certs
```

部署时提供本服务证书、私钥及 CA 信任链，不能分发开发 CA 私钥。组装根运行 `material.Watch(ctx, cfg.TLS.ReloadInterval, log)`（`AIPAY_TLS_RELOAD_INTERVAL`，默认 30 秒）即可热加载：文件变化且新材料有效（服务身份一致、链可信、不少于原有的密钥用途）时原子替换，此后的握手使用新证书与信任链，已建立的连接保持原身份，直到服务端按 `AIPAY_RPC_MAX_CONNECTION_AGE`（默认 54 分钟，上限 1 小时）发出 GOAWAY，再经 `AIPAY_RPC_MAX_CONNECTION_AGE_GRACE`（默认 30 秒）让进行中的调用结束；客户端随后重新握手。grpc-go 会给时长加 ±10% 抖动，默认值加上宽限后每条连接仍不超过 1 小时。健康 Watch 这类长流也会在此时结束，调用方需重新建立。无效或写到一半的文件不会替换当前材料。`material.Check` 可加入就绪检查，证书过期即不就绪。本库未实现证书签发、撤销查询或服务发现。生产监听地址必须配合私网、防火墙和最小调用方名单。每个进程独立日志目录，敏感信息不得拼入自由文本。

## 追踪与任务

服务启动时创建 observability/tracing Runtime；`rpc.ServerOptions.TracerProvider` / `ClientOptions.TracerProvider` 显式注入官方 otelgrpc StatsHandler。mTLS 先验证对端服务身份，再接收 W3C 上下文；trace ID 只用于关联。配置和采样约定见 [observability](https://github.com/Kaivodev/observability#追踪配置与兼容性)。各私有服务已接入运行时和 gRPC span，backend 已接入公网根 span；业务 RPC 尚未注册。

`queue.Load(service, os.Getenv)` 只在确有任务的属主入口调用：`AIPAY_QUEUE_REDIS_URL` 必填并指向独立持久 Redis，不能沿用可淘汰缓存。加载时按上文 `config` 条目中的生产 TLS 要求校验队列地址。其余后缀默认：`NAME=aipay.<service>`、`CONCURRENCY=10`、`POOL_SIZE=20`、`REDIS_TIMEOUT=3s`、`TASK_TIMEOUT=5m`、`MAX_RETRY=10`、`MAX_PAYLOAD_BYTES=1048576`、`SHUTDOWN_TIMEOUT=15s`。

显式创建 `queue.NewProducer(ctx, cfg, provider, accessLog)` 和 `queue.NewWorker(ctx, cfg, provider, accessLog, runtimeLog, handler)`；不自动注册任务。producer 固定队列，允许按任务覆盖 timeout/retry/TaskID；Asynq 超时以秒存储，因此配置和覆盖值都必须是正整数秒，避免亚秒值被截成无效超时。可传 `WorkerOptions{RetryDelay: ownerRetryPolicy}`；默认使用 Asynq 指数退避。先启动依赖再运行 worker，`Check(ctx)` 可加入属主 readiness。停止进程时先停止新任务、排空已有执行；正常完成后释放 Redis。到期 `Run` 返回 `ErrShutdownTimeout` 并取消任务，框架清理继续完成后 `Done()` 关闭；不可提前关闭仍被 Asynq 使用的共享 Redis 连接。`Close()` 仅用于清理未运行实例。任务 handler 必须响应 context；强停/崩溃后任务可能由租约恢复而重复执行。

入队成功只表示受理。业务变更和 `asynqobs.Message` 在属主事务中写 outbox，提交后派发；数据库唯一键保证消费幂等，不能依赖 TaskID/Unique 作为业务事务保证。各私有服务没有模拟支付/认证任务，因此目前不启动业务 worker。

```sh
# 独立临时原生依赖；开发时可追加 --workspace
python3 script/test-tracing.py --postgres-bin /path/to/postgresql/bin
# 同时验证 Collector 与 Jaeger 查询；工具二进制由调用者提供
python3 script/test-tracing.py --collector /path/to/otelcol-contrib --jaeger /path/to/jaeger
```

集成测试使用专属临时 schema/队列与仅测试可见的 RPC，覆盖 HTTP → mTLS RPC → PostgreSQL outbox → Asynq 重试 → 下游 RPC/HTTP，校验 trace/span 父子关系、资源、日志及数据库幂等；另测 panic、超时、SkipRetry/RevokeTask、未知任务、实例重建、独立 OS 进程重启和正常/强制排空。测试重启会发送 SIGTERM 并等待退出；不等同于 SIGKILL/断电及租约恢复验证，也不代表真实业务 outbox 或生产部署已经实现。

## 指标

组装根将同一个 OTel `metric.MeterProvider` 显式传给各组件。传入 nil 时不产生指标，采样器也不会执行数据库查询。服务负责创建和关闭 provider。本版使用 observability v0.3.0，`config.Config` 的指标环境变量接入留待下一步。

| 接入点 | OTel 仪表名 | 属性 |
| --- | --- | --- |
| `rpc.ServerOptions.MeterProvider` | `kaivo.service.ready` | 无 |
| 注册的就绪检查 | `kaivo.service.dependency.ready` | `dependency` |
| 一元服务端、流结束 | `kaivo.rpc.server.duration`、`kaivo.rpc.server.streams` | `rpc_service`、`rpc_method`、`grpc_code` |
| 正在处理的 RPC | `kaivo.rpc.server.active` | `rpc_service` |
| 服务端授权拦截器，含缺省拒绝 | `kaivo.authz.denied` | `rpc_service`、`rpc_method`、`peer_service`、`reason` |
| `rpc.ClientOptions.MeterProvider` | `kaivo.rpc.client.duration` | `rpc_service`、`rpc_method`、`grpc_code` |
| `postgres.ObservePool(mp, "primary", pool)` | `kaivo.db.pool.connections` | `pool`、`state` |
| 同一池的 `Stat()` | `kaivo.db.pool.max_connections`、`kaivo.db.pool.acquires`、`kaivo.db.pool.empty_acquires`、`kaivo.db.pool.empty_acquire.wait`、`kaivo.db.pool.canceled_acquires` | `pool` |
| `queue.ProducerOptions`、`queue.WorkerOptions` 的 `MeterProvider` 和 `TaskTypes` | `kaivo.queue.enqueued`、`kaivo.queue.task.duration` | `queue`、`task_type`、`result` |
| Worker 自带的 Inspector | `kaivo.queue.tasks`、`kaivo.queue.latency` | 前者为 `queue`、`state`，后者为 `queue` |
| `puller.ObserveLag(mp)` | `kaivo.eventstream.lag.events` | `stream` |
| `eventstream.RegisterReceiverSamples(s, db, tables, stream)` | `kaivo.eventstream.stopped`、`kaivo.eventstream.inbox.pending`、`kaivo.eventstream.inbox.oldest_pending` | `stream` |
| `eventstream.RegisterOutboxSamples(s, db, outbox)` | `kaivo.outbox.pending`、`kaivo.outbox.oldest_pending` | `outbox` |
| `telemetry.NewSampler(mp, telemetry.Options{Log: runtimeLog})` | `kaivo.metrics.sample.failures` | `sampler` |

RPC 耗时取秒，状态码使用 gRPC 的名称。健康服务从 RPC 与授权指标中排除。服务端按注册表限定方法，客户端按完整方法路径的格式校验。无法识别时两个方法标签均为 `other`。流计数使用注册描述符，grpc-go 直接拒绝的未知方法计入 `other/other` 耗时。任务类型取属主登记的固定值，其余归入 `other`。连接池名使用最多 32 字符的小写标识符，以字母开头。

每进程创建一个采样器，先登记各流、outbox 和业务仪表，再随服务生命周期启动 `go s.Run(ctx)`。业务使用 `RegisterInt64` 或 `RegisterSeconds`，返回 `[]telemetry.Point[int64]` 或 `[]telemetry.Point[float64]`。采样器名、属性键和点分仪表名的每段均匹配 `[a-z][a-z0-9_]*`。每个点提供全部已登记的属性键，属性值只用固定枚举或部署配置。查询使用传入的 context。默认立即采样，此后每 30 秒一次，每次最多 5 秒，可通过 `Options.Interval` 和 `Timeout` 调整。导出只读缓存，查询失败会撤下该项旧值并计数。

每个活跃的流和 outbox 只登记一次。在已有的流头检查计划里调用 `CheckHead`，首次成功后才有 lag 值。关闭连接池、替换 puller 前，调用 `ObservePool`、`ObserveLag` 返回的注销函数。停止采样器后再关闭它使用的数据库。

## v0.8.0（待发布）

- 新增明文 gRPC、ServiceAccount 投射令牌离线验签、JWKS 热加载以及同端口匿名健康探针。本机栈可选择本地签发方验证这条身份路径。
- `rpc.NewServer` 和 `rpc.Connect` 的传输参数由 `*mtls.Material` 改为 `rpc.Transport`。已有直接传入 `material` 的调用保持源码兼容，默认仍使用 mTLS。

## v0.7.0

- 合入 v0.6.0 的 command digest 能力，包括可选的 `CommandSHA256`、`SessionID` 和 `WebEntry` 声明及其格式校验。
- 新增可选的 gRPC、连接池、Asynq、签名事件流指标和业务采样器，以及本机遥测和日志开关。现有构造调用可继续使用，授权、就绪和排空语义兼容。原有 otelgrpc 追踪显式使用空的指标 provider。

## 名称与兼容性

项目品牌统一为 **Kaivo**，GitHub 组织为 **Kaivodev**。Go module 已迁到 `github.com/Kaivodev/servicekit`，`GOPRIVATE` 使用同样大小写的 `github.com/Kaivodev/*`；协议/签名标识及现有配置键暂时保留原值，属于兼容接口；改名不修改历史账本或协议语义。范围与迁移规则见[命名约定](https://github.com/Kaivodev/docs/blob/main/design/naming.md)。

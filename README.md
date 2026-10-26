# AI Pay 微服务运行库

`github.com/aipay-dev/servicekit` 提供各私有服务共用的运行基础，采用官方 grpc-go。业务处理、用户认证、RBAC、资金模型和数据库 SQL 仍由服务仓库维护。

- `config`：集中校验 `AIPAY_*` 配置；必须提供 PostgreSQL、TLS 和明确的调用方名单。Redis 可选。
- `mtls` / `rpc`：TLS 1.3、双向证书链校验、DNS 校验与 `spiffe://<trust-domain>/service/<name>` 身份绑定；连接复用、unary 超时、调用取消、报文大小限制、关联 ID 和访问日志。
- `postgres` / `redis`：连接池和有界关闭；schema 版本、dirty 标记和服务属主校验。
- `migration`：显式执行服务自身内嵌迁移；数据库级锁串行验证属主与执行迁移，拒绝跨服务和无属主的既有迁移历史。
- `queue`：专用 Redis 的显式 Asynq producer/worker、重试策略、就绪和有界排空；handler 与 outbox 由业务属主提供。
- `cli`：`serve`、`version`、`healthcheck`、`migrate up|down|version`。`down` 只回滚最近一次迁移，可能删除数据。

组装根显式构造资源并注册业务 RPC；框架不自动发现业务。当前各私有服务仅注册标准 gRPC Health，空服务名表示进程及依赖就绪；不存在的业务服务返回 `NOT_FOUND`，不会报告业务可用。调用方身份仅证明服务身份，不能替代用户权限或资源范围检查。

就绪检查覆盖数据库连接、schema 和已配置的 Redis。SIGINT/SIGTERM 后先标记不就绪，再排空 RPC，最后关闭连接池；到期强制退出并返回失败。unary 默认 5 秒、报文默认 1 MiB、停机默认 15 秒。流式 RPC 由调用者控制总时长，业务流必须传递并响应 context；健康 Watch 允许长期保持。客户端不配置应用层自动重试，业务重试必须结合幂等设计。

## 使用与验证

生产使用已发布固定版本，各服务示例配置位于自身 `.env.example`。私有依赖用本机 Git 凭据或只读 `AIPAY_MODULES_TOKEN`；CI 凭据仅允许读取所需模块，禁止放进 Git URL 或构建参数。

```sh
make fmt check
# 仅对隔离的测试实例执行
AIPAY_TEST_DATABASE_URL=... AIPAY_TEST_REDIS_URL=... make test-integration
# 同级工作区四服务的完整进程验证；只创建并销毁自己的临时数据库实例
python3 script/test-workspace.py --workspace .. --postgres-bin /path/to/postgresql/bin
```

真实 TCP 测试覆盖 TLS、服务名单、错误 CA/主机名、无客户端证书、明文拒绝、关联 ID、健康 Watch、依赖故障、消息限制、取消、正常排空及超时退出。存储测试覆盖迁移锁、属主、回滚、dirty/schema 版本和关闭期限。工作区脚本另外启动四个真实服务，检查错误配置、依赖中断、恢复、日志和 SIGTERM。

开发证书仅用于本机，默认 7 天；输出目录必须不存在，证书和私钥权限为 0600：

```sh
mkdir -p ../.local
go run ./cmd/devcert --out ../.local/certs
```

部署时提供本服务证书、私钥及 CA 信任链，不能分发开发 CA 私钥。证书更换后重启服务；本库未实现证书自动签发、热轮换、撤销查询或服务发现。生产监听地址必须配合私网、防火墙和最小调用方名单。每个进程独立日志目录，敏感信息不得拼入自由文本。

## 追踪与任务

服务启动时创建 observability/tracing Runtime；`rpc.ServerOptions.TracerProvider` / `ClientOptions.TracerProvider` 显式注入官方 otelgrpc StatsHandler。mTLS 先验证对端服务身份，再接收 W3C 上下文；trace ID 只用于关联。配置和采样约定见 [observability](https://github.com/aipay-dev/observability#追踪配置与兼容性)。各私有服务已接入运行时和 gRPC span，backend 已接入公网根 span；业务 RPC 尚未注册。

`queue.Load(service, os.Getenv)` 只在确有任务的属主入口调用：`AIPAY_QUEUE_REDIS_URL` 必填并指向独立持久 Redis，不能沿用可淘汰缓存。其余后缀默认：`NAME=aipay.<service>`、`CONCURRENCY=10`、`POOL_SIZE=20`、`REDIS_TIMEOUT=3s`、`TASK_TIMEOUT=5m`、`MAX_RETRY=10`、`MAX_PAYLOAD_BYTES=1048576`、`SHUTDOWN_TIMEOUT=15s`。

显式创建 `queue.NewProducer(ctx, cfg, provider, accessLog)` 和 `queue.NewWorker(ctx, cfg, provider, accessLog, runtimeLog, handler)`；不自动注册任务。producer 固定队列，允许按任务覆盖 timeout/retry/TaskID；Asynq 超时以秒存储，因此配置和覆盖值都必须是正整数秒，避免亚秒值被截成无效超时。可传 `WorkerOptions{RetryDelay: ownerRetryPolicy}`；默认使用 Asynq 指数退避。先启动依赖再运行 worker，`Check(ctx)` 可加入属主 readiness。停止进程时先停止新任务、排空已有执行；正常完成后释放 Redis。到期 `Run` 返回 `ErrShutdownTimeout` 并取消任务，框架清理继续完成后 `Done()` 关闭；不可提前关闭仍被 Asynq 使用的共享 Redis 连接。`Close()` 仅用于清理未运行实例。任务 handler 必须响应 context；强停/崩溃后任务可能由租约恢复而重复执行。

入队成功只表示受理。业务变更和 `asynqobs.Message` 在属主事务中写 outbox，提交后派发；数据库唯一键保证消费幂等，不能依赖 TaskID/Unique 作为业务事务保证。各私有服务没有模拟支付/认证任务，因此目前不启动业务 worker。

```sh
# 独立临时原生依赖；开发时可追加 --workspace
python3 script/test-tracing.py --postgres-bin /path/to/postgresql/bin
# 同时验证 Collector 与 Jaeger 查询；工具二进制由调用者提供
python3 script/test-tracing.py --collector /path/to/otelcol-contrib --jaeger /path/to/jaeger
```

集成测试使用专属临时 schema/队列与仅测试可见的 RPC，覆盖 HTTP → mTLS RPC → PostgreSQL outbox → Asynq 重试 → 下游 RPC/HTTP，校验 trace/span 父子关系、资源、日志及数据库幂等；另测 panic、超时、SkipRetry/RevokeTask、未知任务、实例重建、独立 OS 进程重启和正常/强制排空。测试重启会发送 SIGTERM 并等待退出；不等同于 SIGKILL/断电及租约恢复验证，也不代表真实业务 outbox 或生产部署已经实现。

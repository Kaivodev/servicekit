# AI Pay 微服务运行库

`github.com/aipay-dev/servicekit` 提供四个私有服务共用的运行基础，采用官方 grpc-go。业务处理、用户认证、RBAC、资金模型和数据库 SQL 仍由服务仓库维护。

- `config`：集中校验 `AIPAY_*` 配置；必须提供 PostgreSQL、TLS 和明确的调用方名单。Redis 可选。
- `mtls` / `rpc`：TLS 1.3、双向证书链校验、DNS 校验与 `spiffe://<trust-domain>/service/<name>` 身份绑定；连接复用、unary 超时、调用取消、报文大小限制、关联 ID 和访问日志。
- `postgres` / `redis`：连接池和有界关闭；schema 版本、dirty 标记和服务属主校验。
- `migration`：显式执行服务自身内嵌迁移；数据库级锁串行验证属主与执行迁移，拒绝跨服务和无属主的既有迁移历史。
- `cli`：`serve`、`version`、`healthcheck`、`migrate up|down|version`。`down` 只回滚最近一次迁移，可能删除数据。

组装根显式构造资源并注册业务 RPC；框架不自动发现业务。当前四个服务仅注册标准 gRPC Health，空服务名表示进程及依赖就绪；不存在的业务服务返回 `NOT_FOUND`，不会报告业务可用。调用方身份仅证明服务身份，不能替代用户权限或资源范围检查。

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

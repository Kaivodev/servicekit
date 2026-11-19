# 阶段 2 本地联调栈

两个入口共用业务配置生成器。源码按同级目录布局。运行命令均从 servicekit 根目录开始。八个业务进程之外，开发 HTTPS 收银入口把浏览器请求转给 upstream-sim。验收依赖和目前阻塞资金闭环的具体环节见[演示清单](demo.md)。

## 本机进程

需要 Python 3.9+、Go 1.27、OpenSSL、psql、一个专用 PostgreSQL 18 开发实例和一个缓存 Redis。Go 模块及校验材料须已可用。将管理员连接和缓存连接放在当前终端的环境变量 `AIPAY_DEV_POSTGRES_ADMIN_URL`、`AIPAY_DEV_REDIS_URL`，使用实际的 postgres[ql]:// 和 redis[s]:// URL。数据库 URL 支持主机、端口、百分号编码的用户名/密码、库名以及 sslmode、sslrootcert、connect_timeout、application_name。建议用私有环境文件或交互式秘密输入提供带密码的值。

```sh
python3 dev/native/stack.py prepare
python3 dev/native/stack.py verify
python3 dev/native/stack.py build
python3 dev/native/stack.py migrate
python3 dev/native/stack.py up
python3 dev/native/stack.py status
python3 dev/native/stack.py refresh-market
python3 dev/native/stack.py down
```

- `prepare` 独占创建 `../.local/dev/native/`，检查证书、公钥、签名器和权限，再建六个库。已有目录会拒绝覆盖。只生成配置可用 `prepare --files-only`，之后用相同管理员连接执行 `provision`。数据库步骤失败时保留生成材料，用 `provision` 重试。角色带本栈标记，遇到同名旧角色或他栈库会拒绝接管。管理员 URL 不持久化。
- 数据库名为 `aipay_<服务>`，迁移角色为服务名。IAM、ledger、payment、reconciliation 以迁移脚本授权的 `<服务>_app` 非 owner 身份运行。backend、settlement 使用各自独立的开发角色。notifier 使用 payment 的二进制和自己的 mTLS 身份，upstream-sim 使用内存存储；两者都没有数据库或迁移。
- 缓存 Redis 的 DB 0–5 依次分配给 backend、IAM、ledger、settlement、reconciliation、payment，传入 URL 的 DB 部分由栈替换。队列有独立实例，IAM 和 payment 分别用 DB 1、5。提供 `AIPAY_DEV_QUEUE_REDIS_URL` 会使用已有的持久化、noeviction 队列实例；仅有缓存 URL 时，栈用本机 `redis-server` 和 `redis-cli` 在 127.0.0.1:6389 管理第二个实例，启用 AOF 并将队列数据保存在状态目录。
- `build` 以 `GOWORK=off` 构建七个二进制，继承调用方的 Go 构建缓存。可先用 `build --bin-dir <目录>` 仅做构建。IAM、payment 仍固定 servicekit v0.4.0，联调构建在临时 modfile 中选用含 file signer 的已发布 v0.5.0。其他服务使用自身依赖。部署时各属主应自行确认并升级固定版本。
- 监听地址均为 127.0.0.1。IAM、ledger、settlement、reconciliation、payment、notifier 的 gRPC 端口分别为 9101、9102、9103、9104、9105、9115。backend 公网、平台与卖方监听分别为 8080、8081、8082。模拟上游 API 为 9080，浏览器收银链接用 HTTPS 9443，客户端仅需信任本栈的 `certs/ca.crt`。upstream-sim 重启后原模拟订单与收银链接失效。
- `up` 逐个等待服务就绪；gRPC 使用属主 CLI（含 `notifier healthcheck`），backend 使用 `/health/ready`，upstream-sim 使用 `/healthz`，收银入口通过 HTTPS 转发该探针。失败时仅回收本次成功启动的进程。日志在 `logs/<service>/`，子 PID 在 `run/<service>.pid`。停机指令通过私有 Unix socket 交给持有子进程句柄的父进程。外部 PostgreSQL、缓存与自备队列不会收到停止指令。`status` 在有服务未就绪时返回非零。
- 私有 env、7 天证书、持久化 ES256 签名密钥与公钥、EPay 平台 RSA、密封密钥、上游凭据分别存于 `env/`、`certs/`、`inputs/`、`handoff/`。目录 0700、文件 0600。保留整组状态以继续开发；证书过期应协调重签和重启。原有签名链、密封数据仍依赖原业务密钥。不要打印 env、私钥、数据库 URL、整个 Compose 配置或模拟器凭据接口的响应。
- `refresh-market` 使用刚结束的 UTC 分钟，生成 payment 的十分钟报价样本、reconciliation 自有的两份开发行情观测和一小时覆盖事实。重复刷新同一分钟得到同一报价；历史行情保留供旧订单核验。payment 每次报价重读文件。reconciliation 启动时载入，故命令会单独重启已运行的 reconciliation。报价和覆盖事实均有时限，演示前刷新。
- 商户通知若要实际投递，在 prepare 前提供 `AIPAY_NOTIFIER_EGRESS_PROXY` 和 `AIPAY_NOTIFIER_ALLOWED_HOSTS`，并提供匹配商户地址的回执端。默认预留本地 CONNECT 代理 3128 和精确主机 127.0.0.1。开发 bot 已配置本地测试 token 和 webhook secret，Bot API 测试端预留 9081。两项外部测试端及平台/卖方浏览器入口的 HTTPS 终止见演示清单。

## Compose

需要支持 `env_file.format: raw` 的 Docker Compose（2.30+）、BuildKit 和能读取私有 Go 模块的 `AIPAY_MODULES_TOKEN`。准备脚本沿用相同的 OpenSSL、Go 和同级源码要求。

```sh
python3 dev/prepare.py
dc() { docker compose --env-file ../.local/dev/compose/stack.env -f dev/compose.yaml "$@"; }
dc up -d --build
dc ps -a
python3 dev/prepare.py --refresh-market
dc restart reconciliation
dc down
```

**未在本机验证**。本轮仅静态解析 Compose 和交叉检查配置。新项目名为 `aipay-p2`，独占 `../.local/dev/compose/` 与独立命名卷，避免接管旧五服务栈的用户、卷或密钥。切换前应停止占用相同宿主端口的旧栈或本机进程。普通 `down` 保留卷，`down -v` 会删除数据库和队列卷。

每个数据库服务在自身迁移容器成功退出后启动。Docker 中 payment、reconciliation 与 upstream-sim 共用网络命名空间，以使两份固定 manifest 的 127.0.0.1 域名限制和实际模拟器同时成立。容器间 gRPC 仍核验命名的服务身份；挂载按身份划分。backend、notifier、收银和既有 OTLP Collector / Jaeger 分别有独立容器。宿主端口仅发布到回环，数据库及两个 Redis 在私网。Jaeger UI 端口 16686，OTLP/gRPC 端口 4317。默认代理和 Bot API 回环地址在各自容器内，实际投递/收发需要可达的测试端。

## 验证机记录

先运行 `GOWORK=off make check`，再按本机步骤核对六个迁移退出码和八个业务进程的就绪结果。可用 `AIPAY_TEST_SIM_BINARY=../.local/dev/native/bin/upstream-sim python3 -B dev/native/test_stack.py -v` 单独复查配置生成、行情幂等和进程归属。支付验收另需记录真实的订单/冻结 ID、账本序号、余额前后值、审批人与流游标，见[演示清单](demo.md)。

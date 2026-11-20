# 阶段 2 本地联调栈

两个入口共用业务配置生成器。源码按同级目录布局。运行命令均从 servicekit 根目录开始。八个业务进程之外，开发 HTTPS 收银入口把浏览器请求转给 upstream-sim。验收依赖和目前阻塞资金闭环的具体环节见[演示清单](demo.md)。

## 本机进程

需要 Python 3.9+、Go 1.27、OpenSSL、psql、一个专用 PostgreSQL 18 开发实例和一个缓存 Redis。Go 模块及校验材料须已可用。将管理员连接和缓存连接放在当前终端的环境变量 `AIPAY_DEV_POSTGRES_ADMIN_URL`、`AIPAY_DEV_REDIS_URL`，使用实际的 postgres[ql]:// 和 redis[s]:// URL。数据库 URL 支持主机、端口、百分号编码的用户名/密码、库名以及 sslmode、sslrootcert、connect_timeout、application_name。建议用私有环境文件或交互式秘密输入提供带密码的值。

```sh
python3 dev/native/stack.py prepare
python3 dev/native/stack.py refresh-market
python3 dev/native/stack.py verify
python3 dev/native/stack.py build
python3 dev/native/stack.py migrate
python3 dev/native/stack.py up
python3 dev/native/stack.py status
python3 dev/native/stack.py down
```

- `prepare` 独占创建 `../.local/dev/native/`，检查证书、公钥、签名器和权限，再建六个业务库及独立的 `collection_dev` 开发库。已有目录会拒绝覆盖。只生成配置可用 `prepare --files-only`，之后用相同管理员连接执行 `provision`。数据库步骤失败时保留生成材料，用 `provision` 重试。角色带本栈标记，遇到同名旧角色或他栈库会拒绝接管。管理员 URL 不持久化。
- 数据库名为 `aipay_<服务>`，迁移角色为服务名。IAM、ledger、payment、reconciliation 以迁移脚本授权的 `<服务>_app` 非 owner 身份运行。backend、settlement 使用各自独立的开发角色。notifier 使用 payment 的二进制和自己的 mTLS 身份，upstream-sim 使用内存存储；两者都没有数据库或迁移。
- 缓存 Redis 的 DB 0–5 依次分配给 backend、IAM、ledger、settlement、reconciliation、payment，传入 URL 的 DB 部分由栈替换。队列有独立实例，IAM 和 payment 分别用 DB 1、5。提供 `AIPAY_DEV_QUEUE_REDIS_URL` 会使用已有的持久化、noeviction 队列实例；仅有缓存 URL 时，栈用本机 `redis-server` 和 `redis-cli` 在 127.0.0.1:6389 管理第二个实例，启用 AOF 并将队列数据保存在状态目录。
- `build` 以 `GOWORK=off` 构建七个业务二进制、两个预存开发工具和演示驱动，继承调用方的 Go 构建缓存。可先用 `build --bin-dir <目录>` 仅做构建。联调构建对 IAM、payment 在临时 modfile 中选用含 file signer 的已发布 v0.5.0。其他服务使用自身依赖。部署时各属主应自行确认并升级固定版本。
- 监听地址均为 127.0.0.1。IAM、ledger、settlement、reconciliation、payment、notifier 的 gRPC 端口分别为 9101、9102、9103、9104、9105、9115。backend 公网、平台与卖方监听分别为 8080、8081、8082。模拟上游 API 为 9080，浏览器收银链接用 HTTPS 9443，客户端仅需信任本栈的 `certs/ca.crt`。upstream-sim 重启后原模拟订单与收银链接失效。
- `up` 逐个等待服务就绪；gRPC 使用属主 CLI（含 `notifier healthcheck`），backend 使用 `/health/ready`，upstream-sim 使用 `/healthz`，收银入口通过 HTTPS 转发该探针。失败时仅回收本次成功启动的进程。日志在 `logs/<service>/`，子 PID 在 `run/<service>.pid`。停机指令通过私有 Unix socket 交给持有子进程句柄的父进程。外部 PostgreSQL、缓存与自备队列不会收到停止指令。`status` 在有服务未就绪时返回非零。
- 私有 env、7 天证书、持久化 ES256 签名密钥与公钥、EPay 平台 RSA、密封密钥、上游凭据分别存于 `env/`、`certs/`、`inputs/`、`handoff/`。目录 0700、文件 0600。保留整组状态以继续开发；证书过期应协调重签和重启。原有签名链、密封数据仍依赖原业务密钥。不要打印 env、私钥、数据库 URL、整个 Compose 配置或模拟器凭据接口的响应。
- `prepare` 会生成首份行情。随后先运行一次 `refresh-market`，再生成预存数据集或发布任何资金事件。每次刷新使用刚结束的 UTC 分钟，生成 payment 的十分钟报价、reconciliation 的双来源行情和一小时覆盖事实。payment 每次报价重读文件，命令会重启已运行的 reconciliation 以载入新行情。演示中报价或覆盖即将过期时可再次刷新。
- ledger 启动时从 `AIPAY_LEDGER_DEV_USD_RATES_FILE` 载入 `inputs/ledger/usd-rates.json`，默认每 30 秒重读。文件是 JSON 数组，每个行情分钟追加一条 USDT/USD 观测，`observed_at` 取该分钟的 UTC 起点，`dev-a` 和 `dev-b` 分别报价 `1.0000` 和 `0.9999`。同一分钟重复刷新沿用原记录。追加后超过 64 KiB 时会报错并保留原文件，可归档已登记的旧观测后再刷新。
- 商户通知若要实际投递，在 prepare 前提供 `AIPAY_NOTIFIER_EGRESS_PROXY` 和 `AIPAY_NOTIFIER_ALLOWED_HOSTS`，并提供匹配商户地址的回执端。原生演示使用本地 CONNECT 代理 3128 和精确主机 localhost。开发 bot 已配置本地测试 token 和 webhook secret，Bot API 测试端预留 9081。本机驱动提供这两个测试端，浏览器 Cookie 处理方式见下文。

## 阶段 2 演示驱动

使用本机进程栈。工作目录为 servicekit。新栈按上节准备、构建和迁移。已有上一轮栈先执行 `down`、`provision`、`build`、`migrate`、`demo-config`。最后一条合并 IAM 路由，并补齐 ledger 汇率文件路径、payment 事件拉取、backend 核验服务地址、bot 和 notifier 演示配置。状态、数据库、证书与签名材料沿用原栈。

先在一个终端启动模拟 Telegram API、商户接收端和 CONNECT 代理，并保持运行。

```sh
python3 -B dev/native/stack.py demo serve
```

在另一终端启动业务服务。驱动在预存阶段会按步骤重启本栈，upstream-sim 使用内存存储，应在预存完成后再运行订单场景。

```sh
stack() { python3 -B dev/native/stack.py "$@"; }
stack refresh-market
stack up
stack demo setup
stack demo run main
stack demo run cancel
stack demo run refund-before-release
stack demo run refund-after-release
stack demo run dispute
stack demo run duplicates
```

- `demo setup [iam|registry|packages|seller|channels|merchant]` 可单独运行某个阶段。无参数时依次开通，首个真实失败会停止。独立制包只需已构建的驱动、同级 upstream-plugins 的 v0.2.1 和 go1.27.3 工具链。
- `demo setup iam` 由管理员 1 邀请风控人员（`platform-risk`），管理员 2 批准，风控人员接受邀请后注册自己的 WebAuthn 凭据。风控人员提交 20 秒风控策略和争议裁决；运营登记争议，提交通道、方式、定价、插件和核验账户申请。每份审批材料都按提交人的 IAM 用户 ID 核对，再由两名已登记的审批人分别签署。
- `demo setup seller` 以独立卖方私聊 `/start`、`/balance` 取得账户 ID，再按账户与 Telegram 用户在 IAM 只读事务中查询 `iam_telegram_bindings.user_id`。驱动把六项声明写入 `demo/declarations/seller.json`，用 `iam sellers activate` 登记，管理员 1 随后向同一账户和邮箱发邀请。卖方接受邀请并绑定 TOTP。报告将 `verification_ref` 和 `declared_by` 标为演示值。新栈的 `prepare` 和已有本机栈的 `demo-config` 都从 IAM 迁移属主连接生成私有的 `env/iam-sellers.env`，仅供卖方仪式读取。
- 已在 IAM 登记的演示卖方可指定 `AIPAY_DEMO_SELLER_ACCOUNT_ID` 和 `AIPAY_DEMO_SELLER_EMAIL`。驱动用 `iam sellers list` 核对账户、邮箱并取得登记的用户 ID。已有网页资料的卖方可用私有文件 `AIPAY_DEMO_SELLER_PASSWORD_FILE` 和已绑定时的 `AIPAY_DEMO_SELLER_TOTP_FILE` 提供自己的因子。payment 的 `inputs/payment/seller-reviews.json` 仍需由审核方按 payment README 提供该卖方经核验的摘要、审核人和有效期。
- 浏览器客户端直连回环 HTTP。平台、卖方、商户浏览器分别固定原始 Host 和 HTTPS Origin。每人单独保存 `__Host-` Cookie，每次门户写入前获取对应 CSRF，发送 Origin、X-CSRF-Token 和 Idempotency-Key。商户绑定页使用 HTML 中的 CSRF、enrollment ID 和 completion token。上游收银另走真实 HTTPS，验证本栈 CA。
- 经营域名使用 merchant.aipay.test，通知 origin 为 `http://localhost:9082`，路径为 /notify。payment 拒绝回环 IP 字面量作为登记来源。notifier 在开发配置下允许 HTTP、回环及精确主机 localhost，先在本机解析并固定 IP，再通过 3128 发 CONNECT。演示代理仅接受 127.0.0.1 或 ::1 的 9082 端口，全部监听绑定 IPv4 回环。无需修改 DNS 或 hosts。已有自定义代理或 allowlist 时，应检查它们是否允许这个目标。
- `duplicates` 使用 9122 上的临时 ledger 拉取副本。两个 mTLS 连接读取同一份属主已签回执，副本退出后核对原钱包分录与游标竞争日志。新数据集使用 7 微单位的 duplicate-delivery；旧数据集沿用 normal 的回执重放并要求零增量。旧控制版本样本通过 `ledger-matches pause|resume` 只切换 ledger 的 matches 来源，模拟器原单和签名流持续存在。若在争议登记前失败，续跑同一场景会保留观测顺序。放弃该样本时可执行 `stack ledger-matches resume` 恢复正常拉取；`stack down` 也会停掉临时副本。
- 运行数据在 `../.local/dev/native/demo/`。state.json 含每人自己的演示密钥、计数、密码、一次性材料和步骤断点，仅限本机私有目录。reports 下同名 JSON、Markdown 逐步记录结果。重复运行复用本次开通或原订单。通知记录在 notifications.json，Bot API 删除消息后在 messages.json 清除正文并保留消息 ID。真实入口缺口、有限资金样本和每条验收证据见[演示清单](demo.md)。

## 本机卖方预存

先按上面的步骤建栈、执行迁移，取得演示驱动实际开立的卖方账户 UUIDv7。已有本机栈可保留状态，停机后用原管理员连接依次执行 `provision`、`build`、`migrate`。预存阶段默认关闭，只在本机进程版提供。

```sh
stack() { python3 dev/native/stack.py "$@"; }
stack down
stack refresh-market
stack deposits-on --seller-account-id "$SELLER_ACCOUNT_ID"
stack up
stack status
stack head
# 先按 demo.md 确认 ledger 已登记回执时间可用的汇率，检查钱包科目与三项基线余额，再发布
stack receipt add normal
stack receipt add normal
stack receipt replay normal
stack head
stack receipt add mismatch
stack receipt add unfinalized
```

- `deposits-on` 从演示规格生成 `../.local/dev/native/deposits/`。首次可传 `--spec FILE`；已有数据集按原卖方复用。切换阶段前执行 `down`。`deposits-on --seller-account-id "$SELLER_ACCOUNT_ID" --finalized 3` 后再 `up`，可使待确认样本继续核验。`deposits-off` 后再 `up` 即回到普通阶段，流头与数据库历史保留。
- 独立生成命令为 `python3 -B dev/deposit_scenario.py --seller-account-id "$SELLER_ACCOUNT_ID" --out "$NEW_DIRECTORY"`。默认规格含区块间隔、latest/finalized、每笔转账的 key、块高、链上原始金额、可选回执金额及重放目标。可在规格中同时提供已有的 `address_id`（UUIDv7）和 `deposit_address`，默认按卖方确定性生成。见[默认规格](deposit_spec.json)。
- 创世块取生成时刻的 Unix 整秒，后续每块按 `block_seconds` 递增，默认 3 秒。回执的 `confirmed_at` 取所属区块的 UTC 时间。重启、重读及调整 finalized 高度都复用落盘数据，包括旧版的固定时间。生成新数据集才会采用新的起点。
- `scenario.json` 是生产者输入，含 chain_id、地址绑定、钱包科目、按键索引的 receipts 和 replay_key。每张回执列出交易哈希、全块日志索引、十进制 raw_amount、整数 units、块高、块哈希和 UTC 确认时间。`chain.json` 是独立 RPC 输入，含 chain_id、finalized、有序 blocks 和按交易哈希索引的 receipts；块头、回执和 Transfer 日志使用 EVM RPC 字段与十六进制编码。`bindings.json` 向 reconciliation 提供 version 和有起止块高的 bindings，`reconciliation.env` 选择 bsc-usdt-v1、独立节点和 development_allow 筛查策略。
- 栈分别在各进程私有环境下执行 `kaivo-devcollection serve`、`kaivo-devcollection receipt add|replay SCENARIO RECEIPT_KEY`、`kaivo-devcollection head` 和 `kaivo-devchain serve -dataset FILE [-listen IP:PORT] [-finalized HEIGHT]`。devcollection 在 127.0.0.1:9106 使用 collection 证书与固定的 collection-dev 签名钥匙；仅 ledger 和 reconciliation 可连接。devchain 在 127.0.0.1:8545 只读回答 eth_chainId、eth_getBlockByNumber（第二参数 false）和 eth_getTransactionReceipt。
- 第一笔到账前须开立对应的 collection_wallet，且 ledger 已登记 `observed_at <= confirmed_at` 的 USDT/USD 汇率。驱动在发回执前用只读查询核对。已因缺汇率隔离的转账是终态，补汇率后重放也无法入账。人工核对和重新验收步骤见[卖方预存验收](demo.md#卖方预存验收)。

## Compose

需要支持 `env_file.format: raw` 的 Docker Compose（2.30+）、BuildKit 和能读取私有 Go 模块的 `AIPAY_MODULES_TOKEN`。准备脚本沿用相同的 OpenSSL、Go 和同级源码要求。

```sh
python3 dev/prepare.py
python3 dev/prepare.py --refresh-market
dc() { docker compose --env-file ../.local/dev/compose/stack.env -f dev/compose.yaml "$@"; }
dc up -d --build
dc ps -a
dc down
```

运行中再次执行 `python3 dev/prepare.py --refresh-market` 后，用 `dc restart reconciliation` 载入新行情。ledger 会定期重读挂载目录中的汇率文件。

**未在本机验证**。本轮仅静态解析 Compose 和交叉检查配置。新项目名为 `aipay-p2`，独占 `../.local/dev/compose/` 与独立命名卷，避免接管旧五服务栈的用户、卷或密钥。切换前应停止占用相同宿主端口的旧栈或本机进程。普通 `down` 保留卷，`down -v` 会删除数据库和队列卷。

每个数据库服务在自身迁移容器成功退出后启动。Docker 中 payment、reconciliation 与 upstream-sim 共用网络命名空间，以使两份固定 manifest 的 127.0.0.1 域名限制和实际模拟器同时成立。容器间 gRPC 仍核验命名的服务身份；挂载按身份划分。backend、notifier、收银和既有 OTLP Collector / Jaeger 分别有独立容器。宿主端口仅发布到回环，数据库及两个 Redis 在私网。Jaeger UI 端口 16686，OTLP/gRPC 端口 4317。默认代理和 Bot API 回环地址在各自容器内，实际投递/收发需要可达的测试端。

## 验证机记录

先运行 `GOWORK=off make check`，再按本机步骤核对业务库和 collection_dev 的迁移退出码、所选阶段的进程与流就绪状态。可用 `AIPAY_TEST_SIM_BINARY=../.local/dev/native/bin/upstream-sim python3 -B dev/native/test_stack.py -v` 单独复查配置生成、行情幂等和进程归属。支付验收另需记录真实的订单/冻结 ID、账本序号、余额前后值、审批人与流游标，见[演示清单](demo.md)。

### 2026-11-20 阶段 2 演示验收

在 macOS arm64 验证机上，用本机进程栈完成了一轮完整验收：
- PostgreSQL 18 使用单独实例（55433），与集成测试实例分开。原因是集成测试会建 `iam_app` 等同名角色，栈拒绝接管；
- 缓存 Redis 用 0–5 号库，重建栈前要清空这几个库，否则 backend 会把旧的 Telegram update_id 当成重放；
- 服务版本：protobuf v0.14.0，以及各属主当日的工作区版本。

| 阶段或场景 | 结果 |
| --- | --- |
| `demo setup`（IAM、登记、插件、卖方预存、通道与核验、商户 bot） | 通过 |
| `main` | 通过：商户 +N、平台费用 +F、卖方担保 Q 结束，Q=N+F |
| `cancel` | 通过：未付两次观察后归还；两次观察之间迟付时中止 |
| `refund-before-release` | 通过 |
| `refund-after-release` | 主流程通过；余额不足样本按已知限制停止：没有商户支用入口，随 M5 提现交付 |
| `dispute` | 通过：v0.14.0 裁决触发 → reconciliation 独立复核 → 放币 |
| `duplicates` | 通过：同一签名信封只入账一次；旧控制版本授权被隔离，随后以当前版本裁决收尾 |

运行要点：
- 每个场景开始前刷新行情（`refresh-market`），报价有效期 10 分钟。
- 驱动在每个场景开头发 `/start`，刷新商户的 Telegram 会话（IAM 闲置 30 分钟后过期）。
- IAM 对每个账户的 TOTP 校验（含成功）按 5 分钟 5 次计数，驱动每个窗口最多使用 4 次。
- 卖方审核资料由审核方写入 `inputs/payment/seller-reviews.json`，演示中由操作者代行。

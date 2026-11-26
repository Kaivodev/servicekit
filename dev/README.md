# 阶段 2 本地联调栈

两个入口共用业务配置生成器。源码按同级目录布局。运行命令均从 servicekit 根目录开始。本机 mTLS 与 Compose 都运行两份 Rust 上游网关。开发 HTTPS 收银入口把浏览器请求转给 upstream-sim。验收依赖和目前阻塞资金闭环的具体环节见[演示清单](demo.md)。

## 本机进程

需要 Python 3.9+、Go 1.27、OpenSSL、psql、一个专用 PostgreSQL 18 开发实例和一个缓存 Redis。Go 模块及校验材料须已可用。将管理员连接和缓存连接放在当前终端的环境变量 `AIPAY_DEV_POSTGRES_ADMIN_URL`、`AIPAY_DEV_REDIS_URL`，使用实际的 postgres[ql]:// 和 redis[s]:// URL。数据库 URL 支持主机、端口、百分号编码的用户名/密码、库名以及 sslmode、sslrootcert、connect_timeout、application_name。建议用私有环境文件或交互式秘密输入提供带密码的值。

```sh
python3 dev/native/stack.py prepare
python3 dev/native/stack.py refresh-market
python3 dev/native/stack.py verify
python3 dev/native/stack.py build --workspace
python3 dev/native/stack.py migrate
python3 dev/native/stack.py up
python3 dev/native/stack.py status
python3 dev/native/stack.py down
```

- `prepare` 独占创建 `../.local/dev/native/`，检查证书、公钥、签名器和权限，再建六个业务库、两个网关库及独立的 `collection_dev` 开发库。已有目录会拒绝覆盖。只生成配置可用 `prepare --files-only`，之后用相同管理员连接执行 `provision`。数据库步骤失败时保留生成材料，用 `provision` 重试。角色带本栈标记，遇到同名旧角色或他栈库会拒绝接管。管理员 URL 不持久化。
- 数据库名为 `aipay_<服务>`，迁移角色为服务名。IAM、ledger、payment、reconciliation 以迁移脚本授权的 `<服务>_app` 非 owner 身份运行。backend、settlement 使用各自独立的开发角色。notifier 使用 payment 的二进制和自己的 mTLS 身份，upstream-sim 使用内存存储；两者都没有数据库或迁移。
- 缓存 Redis 的 DB 0–5 依次分配给 backend、IAM、ledger、settlement、reconciliation、payment，传入 URL 的 DB 部分由栈替换。队列有独立实例，IAM 和 payment 分别用 DB 1、5。提供 `AIPAY_DEV_QUEUE_REDIS_URL` 会使用已有的持久化、noeviction 队列实例；仅有缓存 URL 时，栈用本机 `redis-server` 和 `redis-cli` 在 127.0.0.1:6389 管理第二个实例，启用 AOF 并将队列数据保存在状态目录。
- `build` 构建 Go 服务、开发工具和同级 `upstream-gateway` 的 release 二进制。网关需要 Cargo、Rust 1.99.1 和 wasm-tools 1.263.0。Go 默认使用各模块固定版本。protobuf v0.18.0 发布前用 `build --workspace`，属主使用工作区根的 go.work，开发工具使用只含 dev/tools、servicekit、protobuf、observability 的临时 go.work。可用 `--bin-dir <目录>` 单独构建。
- `upstream-gateway-trade` 在 9107 只接受 payment，`upstream-gateway-verification` 在 9108 只接受 reconciliation。两个实例分别拥有 `aipay_upstream_gateway_trade`、`aipay_upstream_gateway_verification` 数据库及同名 owner。网关当前通过私有连接访问开发 PostgreSQL，使用 `sslmode=disable`。各自的 `inputs/<实例>/gateway.toml` 引用独立 KEK 和 TLS 身份，DSN 从 `env/<实例>.env` 读取。网关启动时迁移，TCP 监听就绪后才启动属主。围栏退出可在各自的 `logs/<实例>/process.log` 查看，排除原因后再次执行 `up`。
- 监听地址均为 127.0.0.1。IAM、ledger、settlement、reconciliation、payment、notifier 的 gRPC 端口分别为 9101、9102、9103、9104、9105、9115。backend 公网、平台与卖方监听分别为 8080、8081、8082。模拟上游 API 为 9080，浏览器收银链接用 HTTPS 9443，客户端仅需信任本栈的 `certs/ca.crt`。upstream-sim 重启后原模拟订单与收银链接失效。
- `up` 逐个等待服务就绪；gRPC 使用属主 CLI（含 `notifier healthcheck`），backend 使用 `/health/ready`，upstream-sim 使用 `/healthz`，收银入口通过 HTTPS 转发该探针。失败时仅回收本次成功启动的进程。日志在 `logs/<service>/`，子 PID 在 `run/<service>.pid`。停机指令通过私有 Unix socket 交给持有子进程句柄的父进程。外部 PostgreSQL、缓存与自备队列不会收到停止指令。`status` 在有服务未就绪时返回非零。
- 私有 env、7 天证书、持久化 ES256 签名密钥与公钥、EPay 平台 RSA、密封密钥、上游凭据分别存于 `env/`、`certs/`、`inputs/`、`handoff/`。目录 0700、文件 0600。保留整组状态以继续开发；证书过期应协调重签和重启。原有签名链、密封数据仍依赖原业务密钥。不要打印 env、私钥、数据库 URL、整个 Compose 配置或模拟器凭据接口的响应。
- `prepare` 会生成首份行情。随后先运行一次 `refresh-market`，再生成预存数据集或发布任何资金事件。每次刷新使用刚结束的 UTC 分钟，生成 payment 的十分钟报价、reconciliation 的双来源行情和一小时覆盖事实。payment 每次报价重读文件，reconciliation 检测到行情文件变化后自动重新载入，不需要重启。演示中报价或覆盖即将过期时可再次刷新。
- ledger 启动时从 `AIPAY_LEDGER_DEV_USD_RATES_FILE` 载入 `inputs/ledger/usd-rates.json`，默认每 30 秒重读。文件是 JSON 数组，每个行情分钟追加一条 USDT/USD 观测，`observed_at` 取该分钟的 UTC 起点，`dev-a` 和 `dev-b` 分别报价 `1.0000` 和 `0.9999`。同一分钟重复刷新沿用原记录。追加后超过 64 KiB 时会报错并保留原文件，可归档已登记的旧观测后再刷新。
- 商户通知若要实际投递，在 prepare 前提供 `AIPAY_NOTIFIER_EGRESS_PROXY` 和 `AIPAY_NOTIFIER_ALLOWED_HOSTS`，并提供匹配商户地址的回执端。原生演示使用本地 CONNECT 代理 3128 和精确主机 localhost。开发 bot 已配置本地测试 token 和 webhook secret，Bot API 测试端预留 9081。本机驱动提供这两个测试端，浏览器 Cookie 处理方式见下文。

### 从 UG-4 之前的栈升级

先停栈，备份数据库、队列与整份私有状态目录，再把旧状态目录移出 prepare 的目标路径。devcert 每次都会重签整套身份，新栈要配套使用新数据库、缓存、队列和演示断点。本机使用空的专用 PostgreSQL 实例重新 `prepare`、`build --workspace`、`migrate`。Compose 重新 `prepare`，用新的 Compose 项目名（例如在每条命令加 `-p aipay-ug4`）创建空卷。`--add-missing-credentials` 只维护历史五服务栈，`demo-config` 只用于已具备相应身份和数据库的栈。

### 已有栈升级到 UG-7

已完成 form-md5 开通的本机 mTLS 网关栈可以原地升级，沿用原数据库、卖方与 `demo/state.json`。从目标栈所在工作区的 servicekit 根目录执行，确认该目录含本轮驱动和控制器，同级 upstream-sim 源码已支持 `query_addtime_backdate_seconds`。保持独立终端的 `stack.py demo serve` 运行。

```sh
stack() { python3 -B dev/native/stack.py "$@"; }
stack down
stack epay-on
stack build --workspace
stack up
stack demo setup packages
stack demo setup channels
stack demo run main
stack demo run seller-offline
stack demo run cancel
```

`epay-on` 在停机时补齐模拟器账户和私有 handoff，更新回调路径与核验插件映射，并执行离线校验。凭据字段名取自插件 manifest 的 `secrets` 键名。EPay 交易和核验两侧按 A136 ③ 分别密封同一个商户 KEY，均从 `handoff/epay.json` 的唯一字段 `merchant_key` 读取。升级旧文件时复用模拟器原 KEY 并保留权限，重复执行会跳过已符合要求的文件。命令仅支持本机网关模式。plaintext 使用内嵌插件，Compose 容器的运行状态由 Docker 管理，本机控制器无法检查。

`build --workspace` 同时更新 kaivo-demo 与模拟器。控制器从同级 upstream-sim 复制 go.mod 和 go.sum 到临时目录，以 `GOWORK=off go build -mod=mod -modfile …` 构建 `./cmd/upstream-sim` 到原栈的 `bin/upstream-sim`。若 `stack coverage status` 显示 attestation，放币和取消都需要有效证明，可在上述 `down` 与 `up` 之间执行 `stack coverage file`。

`packages` 制作四个包，`channels` 复用已完成的 md5 步骤，先将旧通道上限双批收窄到 100 分，再开通 EPay。若 EPay 已绑定旧凭据，驱动会重新密封，在支付插件绑定前核对交易凭据的引用和摘要。任一不符时，按通道当前版本双批更新，并保留启用状态。seller-offline 要求 EPay 下线期间拒绝 2.00 元新单，只调优先级仍会让该单落到 form-md5。

### EPay 测试上游联调

用于在网关模式验证一笔 1.11 元真实收款、主动查单和独立放币。先完成常规 `demo setup`，由运营者提供权限为 `0600` 的凭据文件，内含 `EPAY_TEST_BASE_URL`、`EPAY_TEST_PID` 和 `EPAY_TEST_KEY`。两个已发布 EPay 包的 manifest 都须允许该主机。测试上游须显式开通。

```sh
export KAIVO_DEMO_EPAY_LIVE_FILE=/path/to/private/epay-test.env
python3 -B dev/native/stack.py demo setup epay-live
python3 -B dev/native/stack.py demo run epay-live
```

| 场景 | 选路与付款 | 状态 |
|---|---|---|
| `epay-live` | 同一卖方的测试上游只接 111 分，优先级 0 排在两条优先级 1 的模拟器通道前。驱动核对实际通道账户后，将完整付款链接打印到 stdout，付款人可直接打开含 PID 的链接。报告和检查点仅记录 `scheme://host/path`。 | 待验证机 |

联调使用已有商户 V1 应用向 `/mapi.php` 下单。V1 应答无需 RSA 签名，可以交付带 `?pid=…&sign=…` 的完整付款链接。backend 的 V2 应答签名不接受字段值中的原始 `&`，已作为 backend 问题另报。

真实上游的回调到不了本机。payment 对未付订单的主动查单间隔最长 10 分钟，付款后可能还要等约 10 分钟才能确认。驱动每 15 秒检查一次本机账本，`AIPAY_DEMO_EPAY_LIVE_WAIT` 默认 `30m`。超时后可重跑原命令继续等待同一笔订单。

放币并记录网关证据后，驱动自动停用测试通道。付款失败或中途放弃时，可单独执行 `python3 -B dev/native/stack.py demo setup epay-live-off` 停止新派单。可以重复执行，已停用时会跳过。停用不关单、不退款。凭据仍留在本机交易网关和核验网关的数据库中，随本机栈删除。

### 从零重建本机栈

在途订单无法收口（例如上游不可达、结果一直未知）时，可以清库重建。先停栈和 `demo serve`，把 `../.local/dev/native/` 整个改名保留，再用管理员连接对每个 `aipay_*` 库和 `collection_dev` 执行 `pg_dump -Fc` 备份，然后删除这些库以及注释为本栈标记（`kaivo-development-<uuid>`）的角色。`prepare` 会拒绝接管同名的旧角色。之后按本节开头执行 `prepare`、`build --workspace`（二进制未变时也可从备份目录复制）、`migrate`、`refresh-market`，启动 `demo serve` 和 `up`，再执行 `demo setup`。

- 缓存 Redis 可能与其他栈共用，重建时不必清空。backend 把 Telegram 更新摘要按 update_id 在缓存中保留 24 小时；驱动在新状态下从当前毫秒时间起编号，不会与旧栈的编号冲突。旧版驱动建的栈若遇到 webhook 业务码 403（`kaivo:telegram:<bot>:update:<id>` 摘要不符），删除 backend 缓存库中 `kaivo:telegram:*` 键即可。
- 卖方审核资料由 `demo setup seller` 自动写入，见下文运行要点。

## 预发开发材料

从 servicekit 根目录构建 `kaivo-stagingseed`，再运行 deploy 的引导脚本。生成器从当前 kubectl context 读取四个预发命名空间中的受管对象，只通过 stdout 管道交付材料。对象、键名和挂载方式见 [deploy 的 servicekit 开发材料接口](../../deploy/README.md#servicekit-开发材料接口)。

```bash
mkdir -p .bin
(cd dev/tools && GOWORK=off go build -trimpath -o ../../.bin/kaivo-stagingseed ./cmd/kaivo-stagingseed)
export KAIVO_STAGING_SEED="$PWD/.bin/kaivo-stagingseed"
(cd ../deploy && scripts/staging-bootstrap.sh)
```

首次引导逐个应用 9 个 Secret 和 10 个 ConfigMap。sim 域的 `deposit-dataset/chain.json` 起初只有创世块，使 devchain 可在卖方登记前启动。重复引导会复用原私钥、凭据、签名生效时间、卖方审核资料和已初始化的行情。中断后可重跑，生成器从幸存副本补齐共享材料。三域公钥登记表、EPay、交易或查询密钥出现冲突时，生成器向 stderr 写入脱敏诊断，stdout 为空。已有公钥但对应私钥全部丢失时，需要恢复原私钥。请串行执行引导、行情更新和卖方 setup。

启用 KMS 时，iam、ledger、reconciliation、payment 和 backend 各自用本服务的 ServiceAccount 在集群内的一次性 Job 中运行 `kaivo-stagingseed kms-export <service>`，其中 payment 导出事件签名公钥，backend 导出门户 Cookie 包裹密钥，iam 可按规格导出 EPay V2 平台公钥，供三个命名空间发布。`KAIVO_KMS_SPEC_FILE` 指向 deploy 提供的规格，`GOOGLE_APPLICATION_CREDENTIALS` 指向该服务的工作负载身份配置。Job 将签名公钥和经解包验证的包裹密钥写到标准输出。每个服务只生成一次，将结果保存为 `exports/<service>.json`，与规格 `keys.json` 一起保存在 deploy 仓库。本机引导时将 `KAIVO_STAGING_KMS_DIR` 指向这个目录即可离线合并。重复引导复用同一份导出。密钥轮换另行处理。

行情使用刚结束的 UTC 分钟，同一分钟按来源去重。以下 Bash 命令只更新三个 ConfigMap 的四个行情键。单独的 field manager 接管这些键，保留同属 `payment-inputs` 的 `seller-reviews.json`。账本历史达到 64 KiB 或行情达到 1 MiB 限制时，先归档已完成分钟再刷新。

```bash
set -o pipefail
read -r -a kube <<< "${KUBECTL:-kubectl}"
"$KAIVO_STAGING_SEED" market |
  "${kube[@]}" apply --server-side --field-manager=kaivo-staging-market --force-conflicts -f -
```

`KUBECTL` 可设为 `limactl shell kaivo-k3s sudo k3s kubectl`，生成器按空白拆分。生成器、驱动和引导脚本须指向同一集群。模拟 Bot API、商户接收端及 CONNECT 代理预留在 `demo-fixtures.kaivo-sim.svc.cluster.local` 的 8081、8082、3128 端口。

## K8s 担保演示

在独占的 development 预发运行。一次 `setup` 完成 IAM 登记、开发审核、预存充值、通道和商户开通。默认样本给卖方充值 1,000 USDT。驱动核对 collection 钱包和卖方门户可用余额均增加 1,000,000,000 微单位，才继续执行后面的阶段。

### 准备环境

- deploy 需提供包含本版工具的镜像和清单，完成 seed、迁移与部署。业务、账本、核验域沿用各自的 CNPG；sim 域增加 `sim-pg/collection_dev`、devchain 和 devcollection。ledger、reconciliation 要能订阅并验证 `collection.deposits`。后台 SMTP 使用 Mailpit。
- Install Python 3 and kubectl. For embedded mode, use the sibling upstream-plugins v0.2.2 checkout, Go 1.27.3 and its offline module cache. The tools image build context includes the servicekit root module and dev/tools.
- kubectl 身份需要读取 Deployment、Service、Pod、Secret 和 ConfigMap，创建和删除属主 Pod、读取其日志，使用 pods/portforward，创建或 patch 开发输入 ConfigMap，对行情执行 server-side apply，以及 patch 和 watch 三个预存 Deployment。CNPG 策略允许对应的 `<服务>-admin` Pod；sim 库使用 `collection-admin`。
- 夹具使用单副本，状态目录挂载 `emptyDir.medium: Memory`。NetworkPolicy 放行 backend 到夹具 8081、notifier 到 3128，控制端口 8088 只监听 Pod 回环。payment、reconciliation 的热更新输入采用目录挂载。

| 变量 | 默认值与用途 |
|---|---|
| `AIPAY_DEMO_TARGET` | `k8s` 选择预发；默认运行本机栈 |
| `KUBECTL` | `kubectl`。支持 Lima 多词命令，参数中有空格时使用包装脚本 |
| `KAIVO_STAGING_SEED` | 刷新行情时运行的生成器，与引导使用同一版本 |
| `AIPAY_DEMO_CONFIGMAP_SYNC` | `75s`。输入更新后等待 kubelet 投射的时长，接受如 `90s`、`2m` 的正时长，最大 10 分钟 |
| `AIPAY_DEMO_NS_BUSINESS`、`AIPAY_DEMO_NS_LEDGER`、`AIPAY_DEMO_NS_RECONCILIATION`、`AIPAY_DEMO_NS_SIM` | 默认依次为 `kaivo-business`、`kaivo-ledger`、`kaivo-reconciliation`、`kaivo-sim`。清单、seed、夹具和驱动使用同一组名称 |
| `AIPAY_DEMO_PORT_BASE` | First of eight consecutive local ports for the portals, Mailpit, fixture control and PostgreSQL. Default 18080. |
| `AIPAY_DEMO_SIM_PORT` | Local loopback port for simulator control, queries and cashier requests. Default 9080. Use 1–65535 outside the eight-port base range, for example 19080 alongside a native stack. |
| `KAIVO_DEMO_PLUGIN_PACKAGES` | Optional prebuilt Rust package directory for gateway mode. Each of the four plugin directories contains `manifest.json`, `plugin.wasm` and `fixtures/`. |
| `AIPAY_DEMO_FIXTURE_DIR` | 容器内夹具状态目录，默认 `/tmp/demo` |

### Kubernetes gateway overlay

Use a fresh gateway-mode staging deployment or one whose owners have migrated the embedded plugin registrations and credentials. Reconciliation records its mode in `reconciliation_verification_mode`. Keep the private demo state with the deployment that created it. Deploy owns the gateway overlay, database migrations, per-role databases and wrapped keys. Follow its bootstrap and rollout procedure before running setup. [Deploy gateway overlay](../../deploy/k8s/staging/gateway/README.md)

| Deployed setting | Gateway overlay value |
|---|---|
| `payment-config/AIPAY_UPSTREAM_GATEWAY_ADDRESS` | `upstream-gateway-trade.kaivo-business.svc:9107` |
| `reconciliation-config/AIPAY_RECONCILIATION_UPSTREAM_GATEWAY_ADDRESS` | `upstream-gateway-verification.kaivo-reconciliation.svc:9108` |
| `reconciliation-config/AIPAY_RECONCILIATION_PLUGIN_CHANNELS` | `{"sim_form_md5_verify":"sim_form_md5","epay_v1_verify":"epay_v1"}` |
| `payment-config/AIPAY_PLUGIN_CALLBACK_URL` | `http://backend.kaivo-business.svc:8080/callback/{channel_code}`. Payment expands the path per order. The simulator sends GET to `/callback/epay_v1` and POST to `/callback/sim_form_md5`. |
| `payment-config/AIPAY_PLUGIN_INSTRUCTION_TTL` | Defaults to `10m`. Payment accepts 1s–24h at microsecond precision and requires `unpaid_timeout_seconds >= TTL + 1h`. The driver rounds that minimum up to whole seconds and sets the same string on both EPay accounts (default `"4200"`). |

Both addresses select gateway mode. Omit both for embedded mode. A partial overlay stops setup and scenarios. The overlay uses upstream-gateway v0.5.0, payment with `1b38a44` and reconciliation with `abd9cd5` or later. Remove the embedded-only settings and mount a projected ServiceAccount token for each caller with audience `kaivo:upstream-gateway-trade` or `kaivo:upstream-gateway-verification`, respectively. The two gateways verify issuer, audience and caller identity on plaintext gRPC. Allow DNS and development-only private HTTP from both roles to `http://upstream-sim.kaivo-sim.svc.cluster.local:9080`, and simulator callbacks to backend. Keep `AIPAY_PLUGIN_TEST_ONLY_ALLOW_HTTP=true` on payment and `AIPAY_EPAY_TEST_ONLY_ALLOW_HTTP_CASHIER=true` on the development backend. Channel setup registers the simulator Pod IPs for callbacks.

Use the sibling upstream-gateway checkout or set `KAIVO_DEMO_PLUGIN_PACKAGES`. The driver checks the exact simulator hostname, including `AIPAY_DEMO_NS_SIM` overrides, in each package's `domains`. Minimum manifest versions are **0.3.1** for `sim_form_md5`, `sim_form_md5_verify` and `epay_v1`, and **0.2.1** for `epay_v1_verify`. The JSON/RSA pair also gained the staging domain in 0.3.1. The demo installs the form-md5 and EPay pairs.

Bootstrap with this version of `kaivo-stagingseed`. The existing `upstream-sim-private/config.json` gains the `epay-demo` account (style `epay-v1`, numeric PID 1001). `reconciliation-handoff/epay.json` holds its `merchant_key` for independent sealing in the two gateways. Form-md5 uses its existing simulator trade key and `reconciliation-handoff/query.json`. The shared `iam-inputs/routes.json` authorizes `POST /api/v1/platform/channel-accounts/credentials` with `payment.channel.manage` for payment. Embedded payment returns `FailedPrecondition` before storing credentials.

Use an upstream-sim image containing `db63a80` for the seeded EPay account and **`0c27af7` or later** for the full demo. The latter adds per-order `query_addtime_backdate_seconds` for A140 cancellation. Roll out the reseeded simulator and IAM routes before creating orders. The simulator continues advertising cashier links at `http://127.0.0.1:9080`. The driver validates that origin and connects through its selected local port.

### 从空预发运行担保场景

以下 Bash 命令从 servicekit 根目录运行。驱动把登录会话、审批凭据和开户断点保存在私有状态目录中，要求目录属于当前用户且权限为 0700，规则与本机驱动相同。也可以先在该目录上挂载内存盘（tmpfs），使断点不落盘，这是可选做法。Lima 的端口转发须能从宿主机的回环地址访问。

```bash
set -euo pipefail
umask 077
export SERVICEKIT="$PWD"
export STATE="$PWD/../.local/k2-staging"
mkdir -p -m 700 "$STATE" && chmod 700 "$STATE"
# 可选：在空目录上挂载内存盘，使断点不落盘（需要 sudo）。
#   macOS: sudo mount_tmpfs -s 1g "$STATE" && sudo chown "$(id -u):$(id -g)" "$STATE" && chmod 700 "$STATE"
#   Linux: sudo mount -t tmpfs -o "size=1G,exec,nodev,nosuid,mode=0700,uid=$(id -u),gid=$(id -g)" tmpfs "$STATE"

export GOWORK=off GOPROXY=off GOFLAGS=-mod=mod
mkdir -p "$STATE/bin"
(cd dev/tools && go build -trimpath -o "$STATE/bin/kaivo-demo" ./cmd/kaivo-demo &&
  go build -trimpath -o "$STATE/bin/kaivo-stagingseed" ./cmd/kaivo-stagingseed)
export KAIVO_STAGING_SEED="$STATE/bin/kaivo-stagingseed"
```

For an installed gateway overlay, select the same context used for bootstrap. The simulator port below can be used while the native stack is running.

```bash
export KUBECTL="kubectl --context=${KAIVO_DOKS_CONTEXT:?set the staging context}"
export AIPAY_DEMO_SIM_PORT=19080
```

For the embedded local k3s stack, prepare its images and Services.

```bash
export KUBECTL='limactl shell kaivo-k3s sudo k3s kubectl'
export KAIVO_K3S_IMPORT='limactl shell kaivo-k3s sudo k3s ctr -n k8s.io images import -'
(cd ../deploy && scripts/k3s-local.sh images && scripts/k3s-local.sh up)
```

Run setup and scenarios against the selected deployment.

```bash
export AIPAY_DEMO_TARGET=k8s
demo() { "$STATE/bin/kaivo-demo" "$STATE" "$SERVICEKIT" "$@"; }
demo setup -o "$STATE/setup.md"
for scenario in main cancel refund-before-release refund-after-release dispute \
  dispute-refund-before-release dispute-refund-after-release manual-refund manual-refund-failure late-payment; do
  demo run "$scenario" -o "$STATE/$scenario.md"
done
```

In gateway mode, `demo setup` packages and publishes both plugin pairs. The 2.00 orders in `main`, `cancel`, `dispute`, `seller-offline`, `bot-notices`, `statement` and `archived-work` use EPay. Run each with `demo run SCENARIO`. The 1.00 refund orders use form-md5. The duplicates and ledger process-control scenarios require the native stack.

单独执行 `demo setup seller` 可续跑卖方阶段。驱动把 IAM 登记资料的摘要合入 payment 的开发审核列表，刷新行情，发布同一份链、回执与地址绑定，然后依次重启并等待 devchain、devcollection、reconciliation 就绪。ledger 开启预存订阅后一直运行。驱动派生 `ledger-admin` 登记钱包、`collection-admin` 签发 normal 回执，并等待最多 90 秒确认到账。同一预发保留首个卖方和原始区块时间；`demo run deposits` 与卖方 setup 共用充值断点。

状态在 `$STATE/demo-k8s/`；若挂载了内存盘，卸载后私有断点随之丢失。`-o` 支持 setup、单独阶段和 run，扩展名 .json 输出 JSON，其余输出 Markdown。争议退款在跨库环境核对预留 ID、序号、裁决摘要、人工复核记录、签名授权与业务余额。`refund-insufficient` 是另行运行的商户可用余额不足负例，需要独立支用样本。重复回执、`ledger-reader` 和 `ledger-matches` 仍为仅本机栈。通道的回调来源取登记时模拟器 Pod 的精确 IP，Pod IP 改变后按原审批流程更新。

### 集群内夹具

入口为 `/app/kaivo-demo serve-k8s [STATE_DIR]`。将 sim 域 `demo-fixtures-private/bot-token` 只读挂载到 `AIPAY_TELEGRAM_BOT_TOKEN_FILE` 指定的路径，供夹具启动和核验配置请求。`AIPAY_TELEGRAM_WEBHOOK_URL` 默认 `https://merchant.aipay.test/telegram/webhook`。

| 端口 | 行为 |
|---|---|
| 8081 | 模拟 Bot API，核验 token，记录消息、文档和删除 |
| 8082 | 指定 Service 主机上的 POST /notify，验证商户 PID 和签名 |
| 3128 | 仅允许 CONNECT 到夹具 Service 的 8082 |
| 8088 | Pod 回环。GET 读取消息、通知、连接和文档；POST /config 使用 Bearer 认证，更新内存中的 webhook 和商户验签材料 |

驱动在 port-forward 建立后同步夹具，商户签发或更新密钥后再次同步。Pod 重启后，下次运行驱动时会重新装载验签材料。

## 本机 gRPC 传输

默认使用 mTLS。要验证 K8s 的身份路径，先准备本机栈并构建已接入 v0.8.0 传输入口的 iam、ledger、payment（含 notifier）、reconciliation、backend。在发布前使用同级工作区构建。

```sh
stack() { python3 -B dev/native/stack.py "$@"; }
stack down
stack deposits-off
stack build --workspace
stack transport plaintext
stack transport status
stack up
stack status
# 切回默认模式
stack down
stack transport mtls
```

`transport status` 可在运行中查询。切换模式要求所有受管进程已停止，包含独立的 ledger-reader。本机控制器沿用预存阶段的 mTLS 配置，明文模式与 `deposits-on` 互斥。明文模式跳过两个网关与 settlement，payment 使用本机生成的 plugins.json，reconciliation 使用本地密封密钥。切回 mTLS 会恢复网关地址并移除 plugins.json。两种模式各自开通通道，插件版本、凭据引用与审批断点随模式绑定。收银模拟器继续提供 HTTPS，演示驱动与收银健康检查沿用栈的 CA。

受管进程 `devtoken` 在业务进程之前启动、之后停止。签发私钥位于私有状态目录 `native/token-issuer/issuer.key`，权限为 0600。控制器从 `dev/stack_config.py` 的 `PEERS` 反推调用关系，令牌按 `native/tokens/<调用方>/<目标>` 独立存放，有效期 10 分钟，每 4 分钟原子替换。服务运行时仅收到自己的令牌目录、公钥集路径、签发方和命名空间映射。notifier 使用自己的身份，ledger-reader 复用 ledger 身份。磁盘上的服务 env 文件保留 mTLS 配置，Compose 继续使用 mTLS。

## 本机遥测与日志

准备好的栈默认使用文件日志，遥测关闭。先 `down`，选择模式，再 `up`。切换即时写入栈状态，可以复用已经生成的服务 env 文件。

```sh
stack() { python3 -B dev/native/stack.py "$@"; }
stack down
stack telemetry on
stack telemetry status
stack up
stack status
```

本机模式需要已安装的 `otelcol-contrib` 或 `otelcol`，以及支持 OTLP 接收端和资源属性提升的 Prometheus。可在调用 `telemetry on` 时用 `AIPAY_DEV_OTELCOL_BIN` 与 `AIPAY_DEV_PROMETHEUS_BIN` 指定可执行文件。控制器将解析出的路径写入私有的 `native/telemetry.json`。Collector 和 Prometheus 先于业务进程启动，分别监听回环端口 4317 和 9090。配置见 `native/telemetry/`，Prometheus 数据保存在 `native/data/prometheus/`，保留两天。

外部模式使用 `stack telemetry on --endpoint https://collector.example:4317`，端点须包含主机和端口。栈向 Go 服务注入指标端点、`local` 环境、`5s` 导出周期与 `3s` 导出超时（超时须小于周期）。仅对外部非回环 HTTP 端点添加明文许可。通过 `stack telemetry off` 关闭。所有切换均在停机时执行，`telemetry status` 可随时查看。

接入指标 provider 的服务运行并收到调用后，可在本机 Prometheus 的 `http://127.0.0.1:9090` 执行以下 PromQL。

```promql
kaivo_service_ready{deployment_environment_name="local"}
sum by (rpc_service, grpc_code) (rate(kaivo_rpc_server_duration_seconds_count[5m]))
kaivo_queue_tasks{state="pending"}
```

`stack logs stdout` 切到标准输出验证模式，`stack logs file` 恢复文件模式。支持该日志配置的服务在 stdout 模式下将 JSON 随 supervisor 写入 `native/logs/<服务>/process.log`。本机与 Compose 的新 env 文件均默认使用 `AIPAY_LOG_OUTPUT=file`。输出效果取决于各服务二进制接入的日志与指标版本。

## 阶段 2 演示驱动

使用本机进程栈。从 servicekit 根目录按上节准备、构建和迁移。已开通 form-md5 的本机网关栈见 [UG-7 原地升级步骤](#已有栈升级到-ug-7)。

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
stack demo run settle-refunds
stack demo run refund-before-release
stack demo run refund-after-release
stack demo run manual-refund
stack demo run manual-refund-failure
stack demo run late-payment
stack demo run dispute
stack demo run dispute-refund-before-release -o ../.local/dev/native/demo/reports/dispute-refund-before-release.md
stack demo run dispute-refund-after-release -o ../.local/dev/native/demo/reports/dispute-refund-after-release.md
stack demo run duplicates
stack demo run seller-offline
stack demo run bot-notices
stack demo run archived-work -o ../.local/dev/native/demo/reports/archived-work.md
stack demo run statement -o ../.local/dev/native/demo/reports/statement.md
# 需要商户独立支用余额至低于本单净额 N
stack demo run refund-insufficient
```

- `stack demo run settle-refunds` 扫描演示卖方待提交凭证、待复核和异议期内的退款，支持旧订单。驱动按原单金额提交演示 PNG，完成 TOTP 与双人 WebAuthn 复核，等待核验授权和账本入账，核对卖方可用余额增加 Q、退款占用归零。中断后重跑同一命令可续办。
- 已有本机栈在停机时，从目标工作区包含本轮代码的 servicekit 根目录执行 `python3 -B dev/native/stack.py demo-config`，更新 IAM 路由、开启 payment 退款通知，并将 payment 异议期与 reconciliation 异议期下限设为 10 秒。使用含本轮修改的 kaivo-demo 和已迁移的服务启动。
- Run an individual phase with `demo setup [iam|registry|packages|seller|channels|merchant]`. A plain `demo setup` runs them in order and stops at the first failure. Native and Compose use payment.env to select Rust ABI v3. Kubernetes reads both deployed gateway addresses. Embedded mode uses Go 1.27.3 and upstream-plugins v0.2.2. [Package tools and layout](demo.md#网关制包与凭据)
- Gateway setup publishes `epay_v1`, `epay_v1_verify`, `sim_form_md5` and `sim_form_md5_verify`. Orders of 101–10000000 cents use EPay (`epay-demo`, PID 1001) and 1–100 cents use form-md5 (`md5-demo`). In embedded mode form-md5 covers 1–10000000 cents.
- main、duplicates、dispute、seller-offline、bot-notices、statement、archived-work、cancel 下单 2.00 元。本轮退款和 late-payment 场景每单 1.00 元，使用 form-md5 收银。商户 V2、争议裁决及平台运营发起的退款共用卖方举证、双人复核、独立授权与账本核销流程。每笔原单的实际通道记录在报告中。
- `manual-refund` 验证放币后驳回首版凭证、审批第二版，以及卖方监听对平台复核路由返回 404。`manual-refund-failure` 验证放币前失败授权恢复原担保后正常放币。`late-payment` 等待平台取消后才付款，经主动查单和凭证双签结案。`refund-insufficient` 单独运行，报告会记录所需 N 与商户可用余额。
- EPay 两实例的 `unpaid_timeout_seconds` 等于 payment 的付款指令有效期加 1 小时，向上取整秒。默认 10 分钟对应 T=4200 秒。cancel 在关单前只回拨原单查单应答的建单时间 T+120 秒，未付单须经两次间隔至少 5 秒的独立观测才归还担保。迟付单在首次观测后仍可收银付款。
- 第 11 轮四个场景已于 2026-11-24 在本机进程栈通过，结果见[验证机记录](#2026-11-24-第-11-轮演示验收)。卖方场景会切换该金额对应的通道，通知场景会绑定演示商户群。归档场景按 payment 的真实退避等待，可用 `AIPAY_DEMO_ARCHIVE_WAIT=0s` 立即检查并留待续跑。对账场景优先使用已有文件，新栈可能要等到下一次 UTC+8 零点。详见[步骤与证据](demo.md#第-11-轮运行条件)。
- 2026-11-22 的争议退款记录验证的是旧自动退款流程。当前人工退款场景的栈验收待运行。放币后场景也通过平台登记争议，登记失败会把现场状态写入报告。重跑同名场景沿用原单和已签材料。
- `demo run 场景 -o 文件` 在每步结束时更新报告，失败时保留已有证据和错误。`.json` 输出 JSON，其他文件名输出 Markdown。默认的两份场景报告仍位于 `demo/reports/`。
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

两个网关与 payment、reconciliation 共用 upstream-sim 的网络命名空间，插件从回环访问模拟器。upstream-sim 将 9107、9108 发布到宿主回环。网关镜像只从 Rust 构建阶段复制二进制，属主镜像构建时从同级 protobuf 取得本地契约。旧卷的处理见[升级步骤](#从-ug-4-之前的栈升级)。

运行中再次执行 `python3 dev/prepare.py --refresh-market` 即可，reconciliation 会自动载入新行情。ledger 会定期重读挂载目录中的汇率文件。

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
- IAM 对同一 Telegram 用户的 `/start` 按 5 分钟 3 次限流，setup 和前面的场景都计入。驱动按本地记录排队，被拒绝时再等一个完整窗口重试一次；连续执行多个场景时，建议每个场景之间间隔约 2 分钟。
- 驱动在每个场景开头发 `/start`，刷新商户的 Telegram 会话（IAM 闲置 30 分钟后过期）。
- IAM 对每个账户的 TOTP 校验（含成功）按 5 分钟 5 次计数，驱动每个窗口最多使用 4 次。
- 卖方审核资料写在 `inputs/payment/seller-reviews.json`。`demo setup seller` 的“开发卖方审核资料”步骤按 IAM 登记的账户、用户和邮箱生成摘要，以 `kaivo-demo-development` 名义写入 7 天有效的记录，本机与 K8s 相同；payment 每次核对时重读该文件，无需重启。

### 2026-11-24 第 11 轮演示验收

同一验证机与本机进程栈，在已有开通数据上升级到 protobuf v0.15.1 与各属主当日的工作区版本，先迁移再重启服务和 `demo serve`，没有重新开通。

| 场景 | 结果 |
| --- | --- |
| `main` | 通过 |
| `seller-offline` | 通过：下线期间新单被拒，下线前已付款的订单照常放币，重新上线后新单成功；`seller_online_version` 加一，`control_version` 不变 |
| `bot-notices` | 通过：私聊和已绑定群各收到一次"已收款"和"资金已可用"，开通时的审核结果有投递记录 |
| `statement` | 通过：UTC+8 零点日结后私聊收到 zip，清单用 ledger 报表公钥验签，三个文件的 SHA-256 与 4 条分录逐行一致；群内命令只引导私聊 |
| `archived-work` | 通过：订单任务 11 次尝试后归档，运维再认证后填原因恢复，审计和 worker 重新领取均有记录，约 2 小时 26 分钟 |
| `cancel` | 通过：迟付一单现在等到放币，并按该单基线核对卖方 −Q、商户 +N、费用 +F |
| `refund-before-release` | 通过 |
| `refund-after-release` | 主流程通过；余额不足样本仍按已知限制停止，随 M5 |
| `dispute` | 通过 |
| `duplicates` | 通过 |
| `dispute-refund-before-release`、`dispute-refund-after-release` | 2026-11-22 通过，本轮未重跑 |

运行中发现并已在驱动修复：
- 连续运行多个场景时，商户 `/start` 超过 IAM 每用户 5 分钟 3 次的注册限速而被拒。驱动现在按发送者排队，达到上限时打印预计等待时间。
- `cancel` 的迟付一单原先在风控持有时就结束场景，随后自动放币，落进下一个场景的余额测量区间。现在迟付一单要等到放币；每个担保样本取余额基线前，也先等卖方和商户的在途持有归零，2 分钟不归零就停止并列出遗留订单。
- 商户 bot 的 `/orders` 按订单 ID 升序、每页 20 条。演示商户累计超过 20 单后，新单不在第一页。驱动改为按商户单号在 payment 只读查到订单 ID，再用 `/order` 核对 bot 视图。

# 阶段 2 演示验收

验收以 [开发计划](../../docs/plan/development-plan.md)、[审批和资金契约](../../docs/design/contracts.md) 及验证机生成的 `demo/reports` 为准。命令见 [本机运行步骤](README.md#阶段-2-演示驱动)。以下状态区分了驱动覆盖、已执行的验证和仍需属主提供的入口。

## 网关制包与凭据

本机 mTLS 和 Compose 从准备好的 payment.env 读取网关地址。交易实例 `upstream-gateway-trade:9107` 服务 payment，核验实例 `upstream-gateway-verification:9108` 服务 reconciliation。本机 plaintext 与 UG-4b 之前的 K8s 演示继续使用 Go 1.27.3、upstream-plugins v0.2.2 和原凭据流程。

`demo setup packages` 从同级 upstream-gateway 的 HEAD 克隆已提交内容，用该提交的 pluginctl 对 `sim_form_md5`、`sim_form_md5_verify`、`epay_v1`、`epay_v1_verify` 分别 build、package、replay。使用 Git、Cargo、Rust 1.99.1（`wasm32-unknown-unknown`）、wasm-tools 1.263.0 和 Python 3.14.7，构建主机见网关的 build-config.json。源码已含生成好的绑定，重新生成绑定时使用 wit-bindgen-cli 0.63.0。也可将 `KAIVO_DEMO_PLUGIN_PACKAGES` 指向含上述四个包的目录，每包提供 `<code>/manifest.json`、`plugin.wasm`、`fixtures/`。驱动校验 ABI v3、提交及规范 manifest，与存在的同级仓库核对 HEAD，并对原始 manifest 和 wasm 的连续字节计算 SHA-256。

插件 manifest 中 `secrets` 的键是凭据 JSON 的字段名，值是密钥类型。form-md5 使用私有 handoff 目录中的 `trade.json`（`shared`）和 `query.json`（`query_key`）。驱动按预分配通道 ID 写入交易凭据，核验凭据仍需独立见证。

EPay 的两个 manifest 均声明 `{"merchant_key":"shared"}`。`prepare` 将模拟器 `epay-demo` 的 32 位商户 KEY 写入 `handoff/epay.json` 的唯一字段 `merchant_key`。按 A136 ③，交易与核验实例分别密封同一个 KEY。核验见证比对模拟器的 `shared_secret` 及已密封交易凭据的摘要，两份审批材料各自绑定本域引用和同一规范摘要。支付、核验插件版本分别至少为 0.3.0、0.2.0，两份 manifest 均须声明必填字符串 `unpaid_timeout_seconds`。

## 已开通 form-md5 的本机栈

在原栈所在工作区使用含本轮改动的 servicekit 和支持 `query_addtime_backdate_seconds` 的同级 upstream-sim。保持 `demo serve` 运行，从 servicekit 根目录执行以下命令。

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

`epay-on` 仅支持停机的本机 mTLS 网关栈。`build --workspace` 会更新驱动，并用临时 modfile、`GOWORK=off` 从 `./cmd/upstream-sim` 重编原栈的模拟器。开通阶段沿用 md5 断点，对仍使用旧上限的通道双批限额，再完成 EPay 的发布、绑定与核验。若 `stack coverage status` 显示 attestation，放币和取消需要有效证明，可在停机期间、`up` 之前执行 `stack coverage file`。

## 通道与金额

| 模式与通道 | 模拟器账户 | 金额范围（分） | 场景及每单金额 |
|---|---|---:|---|
| 网关 `epay_v1` | `epay-demo`，PID 1001 | 101–10000000 | main、duplicates、dispute、seller-offline、bot-notices、statement、archived-work、cancel，每单 2.00 元 |
| 网关 `epay_v1` 测试上游（显式开通） | 运营者提供的测试商户 | 111 | epay-live，1.11 元，优先级 0 |
| 网关 `sim_form_md5` | `md5-demo` | 1–100 | refund-insufficient、refund-before-release、refund-after-release、dispute-refund-before-release、dispute-refund-after-release，每单 1.00 元 |
| 本机 plaintext、K8s 的 `sim_form_md5` | `md5-demo` | 1–10000000 | 按上述场景取 2.00 或 1.00 元，两种金额均走 form-md5 |

同一卖方使用同一支付方式，payment 按金额筛选候选通道。渠道定价、风控、核验账户各按通道双批，商户平台默认定价只开通一次。报告从 `payment_orders` 读取原单通道和金额，随后按实际账户设置单笔测试场景。payment 用 `AIPAY_PLUGIN_CALLBACK_URL=http://<backend>/callback/{channel_code}` 派发通知地址，EPay 用 GET 通知，form-md5 用 POST。EPay 插件不提供退款，五个退款场景保留 form-md5 的自动退款验收，后续按 UG-8 切换演示为卖方人工退款。

交易和核验配置使用同一个 T。驱动从 payment.env 读取 `AIPAY_PLUGIN_INSTRUCTION_TTL`，加 1 小时后向上取整秒。默认 10 分钟得到 `"4200"`。EPay 的两笔 cancel 订单在商户关单前对各自的模拟器场景写入 `query_addtime_backdate_seconds=T+120`（默认 4320）。它只回拨查单应答的 `addtime`。插件在未付超时后返回 `closed`，上游收银页仍可付款。

## EPay 测试上游联调

网关栈先完成常规开通和商户 V1 应用的收款资格。运营者提供权限为 `0600` 的普通文件，每行一个 `KEY=VALUE`，分别填写 `EPAY_TEST_BASE_URL`（HTTPS 根地址）、`EPAY_TEST_PID`（无前导零的正整数）、`EPAY_TEST_KEY`（无空白和控制字符）。包的发布审批材料中，`epay_v1` 和 `epay_v1_verify` 的 `domains` 都须列出该主机名。

```sh
export KAIVO_DEMO_EPAY_LIVE_FILE=/path/to/private/epay-test.env
python3 -B dev/native/stack.py demo setup epay-live
python3 -B dev/native/stack.py demo run epay-live
```

无参数 setup 只开通常规通道。显式 setup 为同一卖方新增「EPay 测试上游」，沿用已发布的两份插件。按 A136 ③，交易侧通过 payment 的 `StoreChannelCredentials` 密封 KEY，核验侧以 `operator-file/EPAY_TEST_KEY` 见证同一规范摘要，再独立密封。续跑时驱动重新读取文件，三项值须与首次开通一致。报告中的网关地址只展示主机名，PID 标为 `<configured>`。

两条模拟器通道优先级为 1。测试上游只接 111 分，优先级为 0，payment 先选它。联调通过商户 V1 的 `/mapi.php` 下单，因为 backend 的 V2 应答签名不接受字段值中的原始 `&`，已作为 backend 问题另报。

V1 返回 HTTP 200 且 `code == 1` 时，驱动优先取 `payurl`，缺省时取 `qrcode`。核对原单的通道账户 ID 后，驱动将完整链接打印到 stdout，供付款人在浏览器支付 1.11 元。链接可以带上游 PID 和签名等多个参数。原文或任一层 URL 解码后含 KEY 的链接会被拒绝。报告和检查点只保留 `scheme://host/path`。

真实上游的回调到不了本机，payment 对未付订单的主动查单间隔最长 10 分钟。付款后可能还要等约 10 分钟才能确认，驱动每 15 秒检查一次账本付款时间。`AIPAY_DEMO_EPAY_LIVE_CLIENT_IP` 默认 `127.0.0.1`，可设为有效 IP。`AIPAY_DEMO_EPAY_LIVE_WAIT` 默认 `30m`，超时报告“未付款”。重跑同一命令可继续等待原单。

放币和网关取证完成后，风控账号读取测试通道的当前版本，通过平台 `emergency-disable` 停止新派单。付款失败或中途放弃时，运行 `python3 -B dev/native/stack.py demo setup epay-live-off` 可单独停用，已停用时跳过。停用不关单、不退款。凭据仍留在本机交易网关和核验网关的数据库中，随本机栈删除。

## 开通清单

| 操作 | 入口及成功条件 | 当前状态 |
|---|---|---|
| 初始管理员 | IAM 属主 `bootstrap` 封存同一份声明，通过安全邮件及平台 `auth/password/reset` 设置各自密码。两人分别登录、注册 ES256 凭据、重新登录并完成挑战 | 待验证机 |
| 邀请人员 | 管理员 1 在平台 `invitations/platform-staff` 邀请两名审批人和审核、运营、风控人员各一名。受保护邀请由管理员 2 批准。每人用自己的邮件令牌接受邀请，注册 WebAuthn 并登录 | 待验证机 |
| 登记审批人 | payment `approvers register`；reconciliation `registry approvers/dispute-approvers register`。争议登记使用 payment 返回的 key ID 和同一自然人。重试先 list 并核对指纹 | 待验证机 |
| 制包 | 按栈配置选择四份 Rust v3 包或两份 Go v0.2.2 包，上传前核对包摘要 | 待验证机 |
| 卖方 | Telegram 私聊 `/start` 注册，`/balance` 取账户 ID，按账户 ID 和 Telegram 用户 ID 只读核对 `iam_telegram_bindings.user_id`。将六项声明持久化后执行 IAM 属主 `sellers activate`。管理员邀请同一账户和邮箱，卖方接受邀请、绑定 TOTP 并登录。指定已登记账户时用 `sellers list` 核对 | 待验证机 |
| 钱包与预存 | `deposits-on` 为实际卖方生成绑定，ledger `wallets register` 开立 collection_wallet。normal、replay、延后原回执的第三块样本，逐笔核对卖方门户与钱包 | 待验证机 |
| 双域发布 | 运营分别在平台 `plugins`、`verification/plugins` 上传，两名登记审批人各自签署属主生成的规范材料。核对实际提交人的 `requested_by`、材料摘要、两份签署记录和最终状态 | 待验证机 |
| 通道 | 运营申请支付方式、卖方通道、两侧定价和插件启用。风控人员通过 `risk-policies/requests` 提交 20 秒持有期的策略。两名审批人分别签署各项申请，定价和风控生效后再双批启用通道 | 待验证机 |
| 独立核验 | 核对 form-md5 独立查询密钥或 EPay 同钥例外，属主 `registry attestations register` 见证后，运营在 `verification/credentials` 密封凭据，提请双批 `verification/accounts` 和 `verification/enables` | 待验证机 |
| 商户 | 私聊 /start、/totp → 浏览器 GET/POST 绑定页 → /balance、/business_create、/app_create。V1 配回环 CIDR，/key_generate 首次交付并观察相同消息 ID 的 deleteMessage。另建 V2 应用并上传商户公钥，用于关单和退款 | 待验证机 |
| 收款资格 | /access_apply、逐提示 /access_next、/access_submit。审核员在平台读取 revision 及材料哈希后提交 reviews，商户按 /access 返回的版本 /access_enable | 待验证机 |

## 资金场景清单

本表按 UG-7 配置验收。切换前的运行结果见 [验证机历史记录](README.md#验证机记录)。

每个担保样本取余额基线前都会等待卖方和商户的在途持有归零，上一场景遗留的风控持有会先自然放币。若 2 分钟内仍未归零，驱动会停止，并在报告中列出非零余额、待释放笔数和卖方冻结订单。

| 场景 | 真实操作与验收条件 | 当前状态 |
|---|---|---|
| epay-live | 浏览器支付 1.11 元，核对网关建单和查单记录、独立 paid 观测、放币授权及余额，最后停用测试通道。 | 待验证机 |
| main | V1 /mapi.php 下单。卖方门户冻结 Q 后显示模拟收银页，HTTPS POST 付款，模拟器向 backend 回调。payment 主动查单产生 OrderPaid，商户验签并回 success。风险到期后 reconciliation 独立查单、签授权，ledger 放币。卖方减少 Q，商户增加 N，三项费用合计增加 F，Q=N+F | 2026-11-26 本机 mTLS 栈在 EPay 通过 |
| cancel | V2 /api/pay/create、/api/pay/close。两笔独立订单，首次需两条间隔至少五秒的 closed/unpaid 才归还 Q。EPay 查 payment 跳过关单审计、超时推定完成码和取消核验请求。嵌入模式迟付单使用 late_payment。在首条核验后收银付款，要求其后观察到 paid 且没有取消授权。payment 可能先于独立复查查到付款并转入放币核验，所以这条 paid 记在取消或放币核验下都算，再等待放币，按该单基线核对卖方 −Q、商户 +N、三项费用 +F | 2026-11-26 本机 mTLS 栈在 EPay 通过（迟付步骤在断言修正后续跑，沿用原样本证据） |
| refund-insufficient | 已放币原单需由商户真实支用到余额低于 N。提交退款后核对零预留、上游无退款 | 待验证机 |
| settle-refunds | 按演示卖方扫描已有人工退款，续办凭证与双人审批，核对 reconciliation 授权、ledger 核销和卖方余额。可处理旧场景留下的订单，无需原模拟器记录 | 待验证机 |
| refund-before-release | V2 收银付款后、放币前请求全额 /api/pay/refund。查核 ledger PRE_RELEASE 占用、reconciliation 查退款、最终分录、/api/pay/refundquery 和余额复原 | 2026-11-26 form-md5 下单、付款通过；payment 已含 A139 人工退款，`/api/pay/refund` 进入 AWAITING_SELLER，待 UG-8 改写 |
| refund-after-release | V2 放币后先核对 N、F，再全额退款。ledger 的 POST_RELEASE 预留等于 N。核实后商户和费用冲销、卖方恢复 Q。第二笔单要求商户实际可用低于 N 才发退款，核对无预留及模拟器独立 refund-query 查无退款 | 待验证机 |
| dispute | 运营登记原单和商户 /order 证据，卖方在本人门户追加原单证据。风控人员提交放给原收款人的裁决，两名审批人签署，等待 reconciliation 复核与 ledger 落账 | 2026-11-26 本机 mTLS 栈在 EPay 通过 |
| dispute-refund-before-release | 已付款、未放币时登记争议，双方举证后双批退款。A118 将 DISPUTED 原子交接为 PRE_RELEASE 预留 Q。独立查退款成功并签发授权后，ledger 只核销一次，卖方恢复 Q，商户与费用余额不变 | 待验证机 |
| dispute-refund-after-release | 放币后通过平台登记争议，核对原收款账户按争议 ID 从可用冻结 N 到 user_risk_held。双方举证、双批退款后，A119 将冻结转为 POST_RELEASE 预留 N。核销时冲回三项费用 F、卖方恢复 Q，原冻结与退款预留均结清 | 待验证机 |
| duplicates | 原单三份相同回调，待放币核对一次资金效果。另让两个真实 ledger 拉取器读取同一 collection 签名信封，核对完整字节摘要、游标冲突和唯一分录。另一笔单暂缓 ledger 拉取 matches，真实授权签发后由运营登记争议，再恢复拉取，要求原授权因旧版本隔离。风控人员以当前版本提交裁决，两名审批人签署，只有新授权可入账 | 2026-11-26 EPay 三份回调与放币通过；双 ledger 拉取步骤因 PostgreSQL 连接上限失败，待重跑 |
| seller-offline | 卖方 TOTP 再认证后切换本单通道。两端意愿版本各加一，平台 control_version 保持原值；下线期间新单收到签名拒绝，原已付款订单仍放币，上线后另一下单成功 | 2026-11-26 本机 mTLS 栈在 EPay 通过 |
| bot-notices | 用新单触发已收款、资金已可用。按事件 ID 和序号核对 backend 的 sent 投递，按两个单号及法币/USDT 金额核对私聊和群的四个消息 ID，并检查开通审核投递 | 2026-11-26 本机 mTLS 栈在 EPay 通过 |
| statement | 私聊列业务日并收 zip，核对说明、发布公钥、清单签名、三个文件摘要及 CSV/JSON 与当日分录。已绑定群两条命令均引导私聊 | 未纳入 UG-7 验收：ledger 按 UTC+8 自然日出文件，新栈当天无法发布；与上游通道无关，2026-11-24 在 form-md5 通过 |
| archived-work | EPay 用 `api_fault=malformed` 使本单查单持续返回 unknown，嵌入模式用 `query_unknown=true`。PUT `{}` 恢复。平台运维从归档清单选中原任务。WebAuthn 再认证后恢复，按操作人、版本、原次数、原因和 worker 重新领取记录验收 | 未纳入 UG-7 验收：等待时间来自 payment 重试退避（约 2.5 小时），与上游通道无关；EPay 截断应答判为 unknown 已按源码核对，2026-11-24 在 form-md5 通过 |

## 第 11 轮运行条件

- 驱动会按 IAM 的每用户注册限速自动给 `/start` 排队，连续运行多个场景时可能需要等待几分钟。
- 按 README 升级后重启新版 `demo serve`。报表附件按 SHA-256 保存在私有 `demo/documents/`，用于解压收到的原始字节。`messages.json` 与报告记录文件名、大小、摘要和说明。
- `seller-offline` 在收银前取得绑定下线命令的 TOTP 证明，随后用两端的 `seller_online_changed_at`、ledger 的付款时间与放币分录核对先后。场景中断时原通道可能仍处于下线状态；继续运行同名场景会沿用原命令、订单和版本。
- `bot-notices` 与 `statement` 单独运行时都会核对 IAM 中的实际群绑定。尚未绑定时，先在群内发 `/bind_group`，再由商户本人私聊确认。
- `archived-work` 会邀请平台 SRE。EPay 首次失败查询取报告 `首次查单失败[0].occurred_at`。已排定的 pending 查单最多间隔 10 分钟，随后才开始失败退避。payment 默认 11 次尝试，十次退避合计约 2 小时 25 分钟。驱动默认最多等 3 小时，可用 `AIPAY_DEMO_ARCHIVE_WAIT=0s python3 -B dev/native/stack.py demo run archived-work` 创建样本并立即检查。若本单尚未归档，报告以“缺样本”结束，列出次数和下次可领取时间；保持 worker、模拟上游和模拟 Bot API 运行，稍后重跑。分页时只恢复本场景的订单任务。
- `statement` 优先选择最近的已发布商户文件。没有可结算的商户分录时先完成一笔新担保收款；当天分录等 UTC+8 零点后由 ledger 发布，任务每 2 秒检查。旧版本已成功日结但没有文件的日期不会自动补发。等待中可中断并重跑。报告中的 `matched_journal_lines` 是对账当天全部匹配分录的行数。

## 报告和取证

- 报告记录真实步骤、入口、HTTP 状态、backend 业务码或协议错误、请求关联 ID、各步骤的余额和证据。错误时查状态目录 `logs/<服务>/process.log` 和 `logs/<服务>/runtime.log`。认证材料和模拟器收银令牌只进入私有状态。
- 商户本人通过 bot /balance、/orders、/order 取证，卖方通过 `accounts/{seller_account_id}/balance`、`holds?order_id=…` 和订单详情取证。平台订单快照提供原收款账户和锁定报价 Q/N/F。商户主动退款场景使用签名的 V2 退款查询。
- 服务缺少对外读模型的证据在显式 PostgreSQL READ ONLY 事务中读取。payment_outbox 给出事件类型、ID 与 sequence。reconciliation_verification_evidence、reconciliation_authorizations、reconciliation_outbox 给出独立查单、签发时刻及 sequence。ledger_trade_authorizations、ledger_trade_refunds、ledger_trade_reservations 给出执行版本、预留与释放分录。ledger_balances 汇总原三项平台费用；预存另查 ledger_inbox、ledger_trade_deposits 和 ledger_trade_unmatched_receipts。IAM 封存摘要仅用于恢复同一次开通仪式。
- 争议退款的派发顺序使用同一 PostgreSQL 实例的数据库时钟。ledger 在写入预留后、同事务提交前记录交接成功审计。payment 的退款记录须持有同一预留 ID 和 seq，才能进入派发阶段。首次 `refund.dispatch_granted` 记录在上游调用之前，其时间必须严格晚于交接审计。PRE_RELEASE 的 reserve_seq 属于原担保，退款创建时间取自批准时间，两者都不能给出这次交接的时刻。
- 单独记录 `DisputeRulingApproved` 的 disposition 和 reason，例如 `refund_execution_unsupported` 或 `no_matching_pre_release_dispute`。若读取时尚未处置，报告保留该状态。验收使用独立的 `query_refund` 记录、授权所引用的同一证据摘要、模拟器只读 `refund-query` 返回的原单号、退款号与全额，以及授权对应的唯一核销分录。放币后用风控冻结的 final_seq 和退款预留的 final_seq 分别核实转换与结清。
- 每份争议退款报告附有可能影响执行的服务端源码位置和判断依据。放币后登记若返回 404、405 或 501，场景在平台入口以“缺入口”结束。404 也可能表示属主找不到原单，409 可能来自控制版本冲突，需结合报告里的订单状态、版本和请求 ID 定位。
- 2026-11-20 原有场景的实测结果见[验证机记录](README.md#2026-11-20-阶段-2-演示验收)。两个争议退款场景 2026-11-22 通过，第 11 轮各场景 2026-11-24 的结果见[验证机记录](README.md#2026-11-24-第-11-轮演示验收)。

## 卖方预存验收

在 `prepare` 后先运行 `refresh-market`，再用 `demo setup seller` 生成数据集和开立 collection_wallet。创世块取生成时刻，随后每块默认增加 3 秒。回执确认时间取所属区块时间，重启或复用已有数据集时保持原值。

驱动在发布 normal 和 unfinalized 前，通过 ledger 的只读事务核对 USDT/USD 汇率，成功时把版本、观测时间和汇率记入报告。人工发布时可将 `deposits/scenario.json` 中对应回执的 `confirmed_at` 传给 psql 的同名变量，以下查询须返回一行。

```sql
SELECT version, observed_at, rate FROM ledger_usd_rates
WHERE asset = 'USDT' AND observed_at <= :'confirmed_at'::timestamptz
ORDER BY observed_at DESC, created_at DESC, version DESC LIMIT 1;
```

无记录时先确认 ledger 已加载 `AIPAY_LEDGER_DEV_USD_RATES_FILE`。如果旧数据集的回执早于首条观测，新分钟的汇率无法覆盖它。已被隔离的链上转账即使重放也不会入账。要重新验收完整演示，请保留原栈取证，使用新的隔离栈，先刷新汇率，再生成数据集并发布新转账。

**余额快照。** 使用 ledger 属主的只读连接，给 psql 变量 `wallet` 和 `seller` 传入上述编码和卖方 UUID。在发布前、原回执后、核实后、重放后各执行一次，保留三项结果。钱包的 registered 必须为 true。另记录 collection 的 head、两个消费者的 inbox 状态和入账分录序号。

```sql
WITH wanted(code) AS (VALUES
    (:'wallet'), ('unmatched_receipts:USDT:BSC'), ('user_available:USDT:' || :'seller'))
SELECT w.code, a.id IS NOT NULL AS registered,
       COALESCE(b.balance_units, 0) AS units, b.last_seq
FROM wanted w
LEFT JOIN ledger_accounts a ON a.code = w.code
LEFT JOIN ledger_balances b ON b.account_id = a.id
ORDER BY w.code;
```

| 操作与顺序 | 核验和余额检查点（单位 10⁻⁶ USDT） |
|---|---|
| `receipt add normal`，再次 add | 两次返回同一 event ID。钱包和暂挂各增 1,000,000,000。为观察两步，可先以 `--finalized 0` 启动，待记录快照后停栈，改为 2 并重启。reconciliation 核实后暂挂回到基线，卖方增加同额，钱包维持第一次增量 |
| `receipt replay normal` | 新 event ID、下一 sequence，原 receipt_id、载荷和链上元组相同。ledger 复用原分录；reconciliation 隔离对同一回执的第二次认领。三项余额与核实后相同 |
| `receipt add mismatch` | 回执 2,234,567 单位，独立链日志 1,234,567 单位，二者还有尚不足 1 单位的链上尾数。reconciliation 隔离，卖方可用不增。ledger 收到签名回执时仍会增加钱包与暂挂，需逐笔对照基线 |
| `receipt add unfinalized` | 块 3 存在，默认 finalized=2，reconciliation 保持 pending 并重试。提高到 3 后可核实。此样本 raw=1,000,000,000,001，对应 1 单位 |

**验证核实事件先到。** 在发布一笔尚未使用的样本前停栈，例如预留上表的 unfinalized。临时把 `env/ledger.env` 中 AIPAY_LEDGER_COLLECTION_ADDR 指到未监听的本机端口，保留 reconciliation 的真实 collection 地址。启栈并发布样本，待链 finalized 达到样本高度。用 ledger 的只读连接查看 ledger_inbox，确认 reconciliation.matches 的 SellerDepositVerified 已到且 pending，三项余额仍处于该样本的基线。停栈恢复 ledger 地址，重启等待原回执到达。核对 ledger_trade_unmatched_receipts.posting_seq 与 ledger_trade_deposits.unmatched_seq 引用同一笔钱包分录，暂挂回到基线、卖方及钱包分别只增一次。整个验收只提交 collection 回执，核实事件由 reconciliation 签发。

## 契约流接线

| 契约流 | 本栈与验收边界 |
|---|---|
| iam.applications | payment 经 mTLS 拉取，按 IAM 事件 JWKS 验签并检查新鲜度 |
| collection.deposits | 9106 的开发生产者签发回执；ledger 与 reconciliation 拉取，后者还从独立 EVM RPC 核对原转账 |
| payment.orders、payment.pricing | ledger 和 reconciliation 均配置 payment 地址、签名公钥与拉取开关 |
| reconciliation.matches | ledger 与 collection.deposits 一起启用拉取。迟到回执、并发投递和旧授权样本分别核对两条流的游标与入账结果 |
| ledger.trades、ledger.journal、ledger.checkpoints | ledger 提供资金事件与分录、签名检查点读取；本演示以授权的账户与冻结查询、属主分录证据核对。payment 消费 ledger.trades 的放币事实生成账户通知，订单恢复仍可查询账本 |
| payment.account_notices | 仅 backend 拉取，按事件与 chat_id 投递到商户私聊和已绑定群 |
| iam.business_ownership、iam.security | 前者的归属转移和 payment 拉取、后者的 settlement 消费仍待属主接入 |
| collection.sweeps、settlement.wallets、settlement.withdrawals、reconciliation.attestations | 这些流仍待生产端或消费端接线，阶段 2 演示覆盖模拟收款、预存及担保资金流 |

验证机可用隔离实例设置 AIPAY_TEST_DATABASE_URL、AIPAY_TEST_REDIS_URL 执行 `make test-integration`。保留每个场景的两份报告和状态目录内对应服务的日志。

# 阶段 2 演示验收

验收以 [开发计划](../../docs/plan/development-plan.md)、[审批和资金契约](../../docs/design/contracts.md) 及验证机生成的 `demo/reports` 为准。命令见 [本机运行步骤](README.md#阶段-2-演示驱动)。以下状态区分了驱动覆盖、已执行的验证和仍需属主提供的入口。

## 开通清单

| 操作 | 入口及成功条件 | 当前状态 |
|---|---|---|
| 初始管理员 | IAM 属主 `bootstrap` 封存同一份声明，通过安全邮件及平台 `auth/password/reset` 设置各自密码。两人分别登录、注册 ES256 凭据、重新登录并完成挑战 | 驱动已接入，go-webauthn 已独立验证注册、断言和计数 |
| 邀请人员 | 管理员 1 在平台 `invitations/platform-staff` 邀请两名审批人和审核、运营、风控人员各一名。受保护邀请由管理员 2 批准。每人用自己的邮件令牌接受邀请，注册 WebAuthn 并登录 | 待验证机 |
| 登记审批人 | payment `approvers register`；reconciliation `registry approvers/dispute-approvers register`。争议登记使用 payment 返回的 key ID 和同一自然人。重试先 list 并核对指纹 | 待验证机 |
| 制包 | 从本地仓库克隆干净 v0.2.1，检查 HEAD 及工作树，用 go1.27.3 对两包 build、package、replay、verify | 两包已在临时私有状态目录完成四项操作 |
| 卖方 | Telegram 私聊 `/start` 注册，`/balance` 取账户 ID，按账户 ID 和 Telegram 用户 ID 只读核对 `iam_telegram_bindings.user_id`。将六项声明持久化后执行 IAM 属主 `sellers activate`。管理员邀请同一账户和邮箱，卖方接受邀请、绑定 TOTP 并登录。指定已登记账户时用 `sellers list` 核对 | 报告用 `demo_verification_ref`、`demo_declared_by` 标出演示核验引用与声明人，记录 IAM 返回的登记时间 |
| 钱包与预存 | `deposits-on` 为实际卖方生成绑定，ledger `wallets register` 开立 collection_wallet。normal、replay、延后原回执的第三块样本，逐笔核对卖方门户与钱包 | 驱动已接入。验收要求原始转账仅一笔钱包分录 |
| 双域发布 | 运营分别在平台 `plugins`、`verification/plugins` 上传，两名登记审批人各自签署属主生成的规范材料。核对实际提交人的 `requested_by`、材料摘要、两份签署记录和最终状态 | 已接入 IAM 000010 授权，待验证机 |
| 通道 | 运营申请支付方式、卖方通道、两侧定价和插件启用。风控人员通过 `risk-policies/requests` 提交 20 秒持有期的策略。两名审批人分别签署各项申请，定价和风控生效后再双批启用通道 | 需要 payment 独立的有效卖方审核资料 |
| 独立核验 | 比对模拟器交易与独立只读凭据，属主 `registry attestations register` 见证后，运营在 `verification/credentials` 密封凭据，提请双批 `verification/accounts` 和 `verification/enables` | 待验证机 |
| 商户 | 私聊 /start、/totp → 浏览器 GET/POST 绑定页 → /balance、/business_create、/app_create。V1 配回环 CIDR，/key_generate 首次交付并观察相同消息 ID 的 deleteMessage。另建 V2 应用并上传商户公钥，用于关单和退款 | bot 的 19 条路由已纳入 IAM。模拟 Bot API、真实格式 update 与通知验签有单测 |
| 收款资格 | /access_apply、逐提示 /access_next、/access_submit。审核员在平台读取 revision 及材料哈希后提交 reviews，商户按 /access 返回的版本 /access_enable | 待验证机核对真实资格、来源与应用投影 |

## 资金场景清单

| 场景 | 真实操作与验收条件 | 当前状态 |
|---|---|---|
| main | V1 /mapi.php 下单。卖方门户冻结 Q 后显示模拟收银页，HTTPS POST 付款，模拟器向 backend 回调。payment 主动查单产生 OrderPaid，商户验签并回 success。风险到期后 reconciliation 独立查单、签授权，ledger 放币。卖方减少 Q，商户增加 N，三项费用合计增加 F，Q=N+F | 已编排，待取得完整运行报告 |
| cancel | V2 /api/pay/create、/api/pay/close。两笔独立订单，首次需两条间隔至少五秒的 closed/unpaid 才归还 Q。第二笔对原单开启模拟器 late_payment，在首条核验后收银付款，要求观察到 paid 且没有取消授权 | 已编排，待验证机 |
| refund-before-release | V2 收银付款后、放币前请求全额 /api/pay/refund。查核 ledger PRE_RELEASE 占用、reconciliation 查退款、最终分录、/api/pay/refundquery 和余额复原 | 已编排，待验证机 |
| refund-after-release | V2 放币后先核对 N、F，再全额退款。ledger 的 POST_RELEASE 预留等于 N。核实后商户和费用冲销、卖方恢复 Q。第二笔单要求商户实际可用低于 N 才发退款，核对无预留及模拟器独立 refund-query 查无退款 | 正常分支待运行。干净栈缺少可让商户实际支用该余额的入口；驱动保存该笔样本供真实支用后续跑 |
| dispute | 运营登记原单和商户 /order 证据，卖方在本人门户追加原单证据。风控人员提交放给原收款人的裁决，两名审批人签署，等待 reconciliation 复核与 ledger 落账 | 已编排，待验证机 |
| duplicates | 原单三份相同回调，待放币核对一次资金效果。另让两个真实 ledger 拉取器读取同一 collection 签名信封，核对完整字节摘要、游标冲突和唯一分录。另一笔单暂缓 ledger 拉取 matches，真实授权签发后由运营登记争议，再恢复拉取，要求原授权因旧版本隔离。风控人员以当前版本提交裁决，两名审批人签署，只有新授权可入账 | 已编排，双读协调有单测；两副本对同一数据库的游标竞争和旧授权隔离待验证机 |

## 报告和取证

- 报告记录真实步骤、入口、HTTP 状态、backend 业务码或协议错误、请求关联 ID、各步骤的余额和证据。错误时查状态目录 `logs/<服务>/process.log` 和 `logs/<服务>/runtime.log`。认证材料和模拟器收银令牌只进入私有状态。
- 商户本人通过 bot /balance、/orders、/order 取证，卖方通过 `accounts/{seller_account_id}/balance`、`holds?order_id=…` 和订单详情取证。平台订单快照提供原收款账户和锁定报价 Q/N/F。退款查询使用签名的 V2 请求。
- 服务缺少对外读模型的证据在显式 PostgreSQL READ ONLY 事务中读取。payment_outbox 给出事件类型、ID 与 sequence。reconciliation_verification_evidence、reconciliation_authorizations、reconciliation_outbox 给出独立查单、签发时刻及 sequence。ledger_trade_authorizations、ledger_trade_refunds、ledger_trade_reservations 给出执行版本、预留与释放分录。ledger_balances 汇总原三项平台费用；预存另查 ledger_inbox、ledger_trade_deposits 和 ledger_trade_unmatched_receipts。IAM 封存摘要仅用于恢复同一次开通仪式。
- 所有场景均待验证机 PostgreSQL 18 验收。本轮隔离实例在 initdb 的共享内存创建处被沙箱拒绝。

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
| ledger.trades、ledger.journal、ledger.checkpoints | ledger 提供资金事件与分录、签名检查点读取；本演示以授权的账户与冻结查询、属主分录证据核对。payment 的恢复走账本查询 |
| iam.business_ownership、iam.security | 前者的归属转移和 payment 拉取、后者的 settlement 消费仍待属主接入 |
| collection.sweeps、settlement.wallets、settlement.withdrawals、reconciliation.attestations | 这些流仍待生产端或消费端接线，阶段 2 演示覆盖模拟收款、预存及担保资金流 |

验证机可用隔离实例设置 AIPAY_TEST_DATABASE_URL、AIPAY_TEST_REDIS_URL 执行 `make test-integration`。保留每个场景的两份报告和状态目录内对应服务的日志。

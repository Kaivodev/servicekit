# 阶段 2 演示前置条件

验收依据为同级 docs 的[开发计划第 10 轮](../../docs/plan/development-plan.md)、[C2C 交易设计](../../docs/design/c2c-trading.md)与[契约流清单](../../docs/design/contracts.md)。下表的“已具备”指能在属主源码定位到的能力，整条资金路径仍待真实验收。冻结顺序以服务的实际状态机为准：先由 ledger 确认卖方担保，再由 payment 派发上游单并向买方展示指引。

| 验收环节 | 已具备 | 本任务已补 | 缺失、属主与建议 |
|---|---|---|---|
| 卖方预存、可用库存 | ledger 验签到账先入暂挂；reconciliation 核对独立链证据后签发 SellerDepositVerified；ledger 校验原回执再重分类 | collection 专用证书、持久 ES256、公钥 pin 和两个接收方的预留地址 | collection 仓库缺位，独立开发链、历史绑定、钱包科目和可复验的收款样本待准备。见下节 |
| 平台与双人审批 | IAM 邀请、密码和 WebAuthn 登录；payment、reconciliation 对真实审批材料另验两份断言，发起人不能自批 | 一致的 RP ID 和 HTTPS origin、门户路由登记、IAM 安全邮件队列/开发目录、签发与验证公钥 | IAM 提供一次性且可审计的初始管理员开通；payment、reconciliation 各自登记人和钥匙。演示驱动需隔离多个自然人的软件认证器并保存计数 |
| bot 注册、Telegram 绑定、TOTP | backend webhook 与 IAM 的私聊 /start、/bind、/totp；IAM 建个人账户、幂等更新和一次性 TOTP 绑定 | 本地 bot token、webhook secret、测试 API 地址和 enrollment origin | 演示驱动应以真实 update JSON、不同 update_id 和正确的 X-Telegram-Bot-Api-Secret-Token 投递私聊。提供本地 Bot API 的 getWebhookInfo（URL 与配置一致）、sendMessage、deleteMessage；群场景另需 getChatMember。已有门户账户的 /bind 需经近期 TOTP 取得绑定码。准备 enrollment 页 HTTPS 终止 |
| 商户业务、应用和 EPay | IAM 的 CreateBusiness、CreateApplication、GenerateEpayV1Key、上传 V2 商户 RSA 公钥、获取平台公钥；iam.applications 在 payment 投影 | IAM 本地 sealer、持久身份签名、平台 RSA DER 及其验签公钥、EPay 路由和缓存限速 | backend 的 bot 尚缺业务/应用写命令。backend 或后续驱动须以真实 backend mTLS 身份，对每个写操作执行私聊 Authorize，绑定目标、规范命令摘要、新 TOTP 和 MFA_RECENT，再调 IAM。V1 需开关、来源 CIDR，KEY 仅首次交付；V2 由商户持私钥、IAM 登记 SPKI。创建应用后仍要支付方式开通 |
| 模拟插件、通道与核验账户 | upstream-plugins 有支付/核验两类包；payment、reconciliation 分域上传、回放、审批、启用；模拟器有独立 query 凭据 | 选 form-md5 作为演示通道。交易 ref 为 sim-md5-v1，模拟账户 md5-demo，gateway 为 http://127.0.0.1:9080；reconciliation 的插件通道映射、本地密封器与只读凭据已生成 | 按下文操作制作并上传包。payment 当前的卖方审核来源是 Unavailable，需属主提供可信审核适配与 C2C 商户资格/域名审核入口。reconciliation 需要离线登记只读来源见证，绑定通道、凭据摘要、有效期、审计，再由 RPC 密封、两人审批和启用 |
| EPay 下单、冻结、模拟收款、回调、查单 | backend 验签限速并调用 payment；payment 核资格、锁定版本、向 ledger ReserveTrade、取得冻结再派发；回调验签后由主动查单确认 | mTLS、模拟器及 HTTPS 收银页、backend /callback/sim_form_md5、payment 证据目录、dispatcher/worker、队列、报价文件 | 需卖方已有可用、与收款户不同、有生效的支付方式、两侧定价、通道/卖方绑定、已审批支付插件与风控版本；按实际回调来源配置通道策略。notification 测试另需受控 CONNECT 代理与可回执商户端，payment 负责签名，notifier 只投递 |
| 风控期、独立查单与放币 | payment 签 OrderPaid v2；reconciliation 根据原冻结、风控截止、独立只读查单、定价/行情、屏障与覆盖签授权；ledger 有三种授权的记账规则 | 开启 payment.orders/pricing 拉取、独立验证宿主、争议登记表校验、同分钟两份行情观测与有时限的开发覆盖 | **ledger** 缺生产装配的 payment.orders 网络 puller；reconciliation.matches 在 ledger 与 collection 同开关。先补齐有版本白名单的接收与可恢复启动，确保到账事实/授权乱序时保持 pending。payment 的风控没有环境变量覆盖；以正常双审批 RiskPolicyChange 明确设置 hold_duration_seconds（可为 0，建议短正数以展示到期前后），ledger 与 reconciliation 仍按权威时间判断 |
| 商户余额、管理端和卖方门户 | ledger 释放时给原收款账户记 N、平台费用记 F，Q=N+F；ledger、payment 有卖方/平台只读 RPC；IAM 支持独立网页入口 | 三个 HTTP 监听、IAM/payment/ledger 对端、门户 origins 和 cookie 密钥、精确 IAM 路由登记 | backend 已提交基线 b6e9b40 的门户主要为占位；本次只读工作树中另有正在接入的会话/CSRF、通道与卖方余额代码，须按最终版本逐路实测平台审批、卖方仅本人可读。准备 admin.aipay.test 与 seller.aipay.test 的本地 HTTPS 终止。卖方首次开户还需 IAM 的 iam_seller_activations。EPay merchant/info 仍缺可用的商户余额映射，以 ledger 经授权的原账户读模型或属主只读验收查询核对原账户余额增量 |
| 未付取消 | payment 发起原单关闭；reconciliation 要求两次独立 closed/unpaid 观察；ledger 接受绑定当前版本的取消授权才还卖方 Q | 迟到付款复查窗口在开发环境设为 5 秒，模拟器可设置迟付或关单不支持 | protobuf/payment/reconciliation 约定并接通首次核验的触发与重驱；验证两次观察期间迟付不会解冻，未知结果保留占用 |
| 已付未放币退款 | payment 先以当前版本占用原担保 Q，再向模拟上游原路全额退；reconciliation 独立 query_refund 核对原单，ledger 按核实终态处理 | payment 与 verification 各用自己的凭据，支持模拟成功、失败、未知 | protobuf/payment/reconciliation 接通退款核验触发；ledger 补网络接收与支付事件类型覆盖。验收失败分支恢复原风控，未知继续占用，成功才归还卖方 |
| 已放币全额退款 | 先从原收款人可用余额预留 N；独立核实后反向冲销 N 与原三项费用 F，卖方恢复 Q | 原报价、锁定版本和开发覆盖可用于两域校验 | 同上，另需账户确有 N 和有效覆盖。验证余额不足时不先退法币，失败释放预留，未知保留，重试仅一笔反向分录 |
| 争议与幂等 | payment 登记双方证据、等待 ledger 屏障后发布 OrderDisputed；双人裁决，reconciliation 从 payment 读裁决并用自己登记的公钥复核；ledger 有放币前退款交接和放币后可控余额冻结规则 | dispute registry、同 RP 校验和 payment 对端；模拟器可重发相同回调 | payment/reconciliation/ledger 完成上述触发和传输；演示驱动覆盖旧 control_version、重复回调、重复信封、批准后重启。保存事件 ID/sequence、冻结版本、分录序号及前后余额；同一授权与同一链转账只能产生一次资金效果 |

## 卖方预存建议

1. 在开发工具或未来 collection 仓库实现**只用于开发的 collection 流生产者**，持有本栈 collection 的 mTLS 身份和事件私钥。提供 ListEvents 和 GetStreamHead，持久化同一串 sequence、prev_digest 和 event ID，使用标准 SignedEvent 的 ReceiptConfirmed schema 1，仅允许 ledger 和 reconciliation 拉取。
2. 准备独立的本地 EVM 链（31337）或只服务于开发的确定性 EVM RPC fixture。其数据集独立于生产者提交的回执，覆盖 chainId、finalized 块、指定高度的 canonical 块、交易回执及全块 log index。选用核验器已登记的 BSC USDT 合约，保持 ERC-20 原始金额到 10⁻⁶ USDT 的转换一致。预置有区块高度范围的地址→卖方账户绑定，在 ledger 开立对应 collection_wallet 科目。
3. 在第二阶段部署时启用 AIPAY_RECON_DEPOSITS、独立节点、bindings 文件、screening policy 和 development_allow，再启用 AIPAY_LEDGER_DEPOSITS。先收到回执时只增钱包资产与 unmatched_receipts；只有 reconciliation 签发引用原 collection_event_id 的 SellerDepositVerified 后，ledger 才从暂挂转到卖方可用。验收前后各查一次暂挂、钱包、卖方余额，重放和颠倒到达次序，钱包只增加一次。
4. **对 line-6000 的影响**：复用已有的验签、EVM 解析、历史绑定、复核、账本规则和迁移，不需改变事件 schema 或资金判定。现有 ledger 在构造阶段同时连 collection 和 reconciliation，后者的交易 jobs 又会连 ledger。启用预存后的冷启动需由 ledger 拆开消费者连接生命周期、支持后台重连，或由联调部署分两阶段启动。只读盘点未改属主。直接写余额、手填核实事件或把 coverage 文件当预存会跳过待验收的不变量。

## 审批、包与数据准备

- IAM 的迁移不会产生管理员。IAM 属主需要隔离开发环境的初始化仪式，建立至少两名不同的初始管理员及已核实资料。高权限邀请由另一名管理员批准；管理员与审批人角色互斥。操作员与两名审批人分开。通过受限的首次密码会话完成 WebAuthn 注册，重新登录取得近期认证。登录凭据保存在 iam_webauthn_credentials。
- 业务审批还需 payment_approver_people / payment_approver_keys，reconciliation_admin_people / reconciliation_admin_keys。独立复核 payment 争议裁决另需 reconciliation_dispute_people / reconciliation_dispute_keys 登记能验证 payment 审批人的材料。各属主离线维护 IAM 用户→自然人、公钥、credential ID、有效期与撤销；应用运行账号无登记权限。演示驱动用软件认证器为各人保存独立 ES256 密钥、credential ID 和计数，按每次 challenge、RP ID、origin、UP/UV 生成 WebAuthn 注册与断言。IAM 登录断言和两份审批断言分别生成。
- 用 upstream-plugins 的**干净 v0.2.1 checkout** 构建 pluginctl，预置准确的 go1.27.3 工具链。对 plugins/sim_form_md5、plugins/sim_form_md5_verify 各用 pluginctl build、package、replay、verify；输出放在 checkout 外。包内保留 manifest.json、plugin.wasm、fixtures/ 及匹配的摘要、回放报告、source_commit。该 tag 两个 manifest 的插件版本仍为 0.2.0。pluginctl 会把含未跟踪文件的工作树也标为 uncommitted，上传会拒绝。当前同级 checkout 有未跟踪的 .DS_Store，验证机可从本地仓库克隆一个干净的 tag 副本。
- payment 上传 payment 包，两人发布，配置初始停用通道、卖方审核、凭据 ref、支付方式、定价与风控；双审批绑定/启用插件并启用通道。reconciliation 单独上传 verification 包、双人发布；属主先核实独立来源并在 reconciliation_credential_attestations 登记见证，再将 handoff/query.json 的原始凭据经 StoreVerificationCredentials 密封，提交/双批核验账户、申请/双批启用。审批的 channel_code 为 sim_form_md5，两个账户配置里的 gateway、account_id 相同，凭据用途不同。商户支付方式审核与平台通道开关分别完成。

## 契约流与当前接线

| 契约流 | 生产方 → 接收方 | 本栈与属主现状 |
|---|---|---|
| iam.applications | iam → payment | 已配 mTLS、IAM 事件 JWKS、受众和 payment 新鲜度检查 |
| iam.business_ownership / iam.security | iam → payment / settlement | 前者的归属转移协议和 payment puller 待接；后者 IAM 有安全事件和读 ACL，settlement 缺消费者 |
| payment.orders / payment.pricing | payment → ledger、reconciliation | payment 签两流；reconciliation 配 payment 地址与 JWKS，分别拉取。ledger 有 OrderPaid inbox 入账规则，缺这两流的对端装配和完整类型处理 |
| collection.deposits | collection → ledger、reconciliation | 已备两方地址和 collection JWKS。默认均关闭，待生产者及独立 EVM/绑定就位 |
| collection.sweeps | collection → ledger、reconciliation | 工作区缺生产者和运行接线 |
| settlement.wallets / settlement.withdrawals | settlement → ledger、reconciliation | settlement 当前为基础服务。生产者及两个接收方的对应拉取待属主实现 |
| reconciliation.matches | reconciliation → ledger、settlement | 已签名，ledger 已配地址与 JWKS，与两个预存来源共同启用；settlement 缺接收器 |
| ledger.trades | ledger → payment、reconciliation、settlement | ledger 内核签名/出流；三个接收方均无此流的可配置 puller。payment 恢复通过认证的账本查询；reconciliation 已接冻结明细 RPC |
| reconciliation.attestations | reconciliation → settlement | 两端均待实现 |
| ledger.journal / ledger.checkpoints | ledger → settlement、reconciliation | ledger 提供 JournalService 哈希链和签名检查点流；下游无相应持续拉取配置。journal 不逐条签名 |

## 验证与待定项

本轮运行了两种栈的配置自测（开发秘密只在内存）、建库 SQL 输入检查、分钟刷新幂等，实际验证了托管 Redis 的认证、队列分库与 AOF 重启恢复，并通过真实 upstream-sim 的构建/race 测试、进程就绪/再启动/停机与外部 PID 保护，并以真实 HTTPS 收银 GET/POST 和独立只读凭据查到 paid。此 HTTPS 实测使用进程管道提供的临时测试证书，未验证整套新 CA/mTLS。Compose YAML 可解析，**未在本机验证**。沙箱拒绝写同级状态目录，完整 prepare/证书文件核验未运行成功；离线模块缓存缺失锁定的私有包、pgx v5.11.0 等，六个数据库服务构建和 servicekit make check 受阻。未运行 PostgreSQL、迁移、八业务进程全栈和资金验收。

需要确定 collection 演示生产者的归属、独立节点或固定链证据方案，初始管理员/审批人登记的属主与仪式，以及本轮是否接受用经授权的属主 RPC/账本只读证据作为中间检查点。计划要求的 bot、门户和资金闭环仍应分别保留真实入口的最终验收记录。

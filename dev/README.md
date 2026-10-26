# 本地四服务联调

同级工作区需要 `iam`、`ledger`、`settlement`、`reconciliation`；各自固定依赖已发布的 `servicekit`。需要 Docker Compose、Go，以及可以读取 `observability`、`servicekit` 的 `AIPAY_MODULES_TOKEN` 环境变量。

在 servicekit 仓库运行：

```sh
python3 dev/prepare.py
docker compose --env-file ../.local/dev/stack.env -f dev/compose.yaml up -d --build
docker compose --env-file ../.local/dev/stack.env -f dev/compose.yaml ps
docker compose --env-file ../.local/dev/stack.env -f dev/compose.yaml exec iam /app/aipay-iam healthcheck
# 保留数据库；再次 up 可以继续开发
docker compose --env-file ../.local/dev/stack.env -f dev/compose.yaml down
```

准备脚本拒绝覆盖已有状态，生成随机开发密码、短期证书和独立日志目录。私钥保持 0600，服务容器以当前开发用户 UID/GID 读取；数据库和缓存只在 Compose 私网，gRPC 仅映射宿主机回环地址 9101–9104。四个数据库使用不同用户并撤销 PUBLIC 连接权限。迁移容器成功退出后才启动对应服务。

`../.local/dev/stack.env` 含开发凭据，禁止提交、打印或用于生产。不要对有需保留数据的栈使用 `down -v`；它会删除数据库卷。证书到期后需有计划地更换并重启；准备脚本不替换现有密钥。服务日志在 `../.local/dev/logs/<service>/`。

尚未接入认证、支付、账务或结算业务。健康成功只说明进程和依赖就绪；没有模拟业务成功接口。容器构建与远端 CI 的执行结果应以本次实际验证为准，不能由配置文件存在推断通过。


队列 Redis 独立于缓存，使用独立密码、AOF `everysec`、`noeviction` 和命名卷；这仍存在故障持久性窗口，不能替代业务 outbox/幂等。已有开发目录可运行 `python3 dev/prepare.py --add-queue-credentials`，只追加缺少的队列密码，不重建数据库凭据或证书。具体任务属主使用 `AIPAY_QUEUE_REDIS_URL=redis://:<queue-password>@queue-redis:6379/0`，目前四服务没有注册业务任务。

本地 Collector 监听回环端口 4317，服务通过 Compose 私网发送 OTLP；宿主机 backend 可设置 `AIPAY_TRACE_ENDPOINT=http://127.0.0.1:4317`。Jaeger UI 位于 http://127.0.0.1:16686，按响应 `X-Trace-ID` 查找链路。Jaeger 使用有界内存存储，重启丢弃追踪；生产需独立的存储、TLS/访问控制和保留策略。Collector/Jaeger 不参与服务 readiness。此 Compose 仅用于开发，不对公网开放查询或收集端口。

`collector.yaml` / `jaeger.yaml` 已用于原生二进制配置校验与实际链路查询；容器执行和远端 CI 本轮仍按约定留待具备环境后验证。

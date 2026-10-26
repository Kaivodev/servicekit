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

# AI Pay 微服务运行库

- 只提供配置、mTLS/gRPC 生命周期、连接与迁移工具；不拥有业务模型、业务数据库、用户身份或授权规则。
- 使用官方 grpc-go；默认要求可验证的双向 TLS 和明确服务身份，不提供跳过验证或明文生产模式。
- 各服务显式组装依赖、独立拥有数据库和迁移；不引入全局 ServiceContext、完整 Store 或隐式注册。
- 连接串、私钥、token、请求正文不进入日志和错误响应；对外错误使用安全消息。
- 公共库使用版本化发布，保持已发布版本不可变，不提交本机绝对路径 replace。
- 修改代码执行 make fmt check；涉及存储或实际通信时运行隔离依赖与真实 TLS 集成测试。
- 文档保持简短，区分可运行基础与未实现的业务能力。未授权不提交或推送。
- 提交遵循 Conventional Commits，正文包含 AI-Context、Decisions、Validation、Follow-up。

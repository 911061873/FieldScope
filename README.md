# FieldScope

**FieldScope** 是一款面向企业的 B/S 架构细粒度数据连接器平台（**Python FastAPI 后端 + Vue 3 / Naive UI 管理台**），为第三方业务系统接入与 AI Agent（MCP）调用提供统一的三方平台接入、动态认证续期、用户级数据范围隔离与字段级权限管控。

---

## 核心特性

- **双轨角色与权限管控**：
  - **平台内部角色**：限制用户在 FieldScope 管理后台本身的功能菜单与管理接口权限（内置 `super_admin` / `platform_admin` / `auditor` / `member`）。
  - **外部数据角色**：控制外部调用能力，精确到 4 个层级——**三方平台 → 接口 / MCP 工具 → 数据范围（请求前校验/强制参数注入 + 响应后行级过滤）→ 字段权限（白/黑名单裁剪 + 脱敏）**。
  - 多外部角色采用**默认拒绝、允许取并集、显式拒绝优先、脱敏安全优先**的合并语义。
- **三方平台双协议接入**：
  - **REST API 平台**：注册 HTTP 接口后，同时提供 `/gateway/{platform_code}/{path}` 反向代理与自动暴露为 MCP Tool。
  - **远端 MCP Server**：支持 Streamable HTTP / SSE 协议，管理台一键同步上游 `tools/list`，纳入同一套外部角色管控与返回字段裁剪。
- **平台级统一认证与动态续期引擎**：
  - **静态授权**：支持配置传递位置（`Header` 或 `Query`）、参数名、前缀与 AES-256-GCM 加密值。
  - **标准 OAuth2**：支持 `client_credentials` 与管理员 `authorization_code`（`refresh_token` 持久化自动续期）。
  - **自定义 HTTP 获取 Token**：自定义请求模板、加密变量 `{{ secret.* }}`、JSONPath 响应提取、可选独立续期请求。
  - **完整续期闭环**：过期前提前刷新 + 平台级 Single-Flight 并发锁 + HTTP 401 或自定义响应体业务错误码（如 `$.code == 40001`）自动刷新并重放一次。
- **双模式数据面身份识别**：
  - 用户个人 API Key（`Authorization: Bearer fs_usr_*`）：适合 AI Agent / MCP Client 直连。
  - 外部应用代调用（`Authorization: Bearer fs_app_*` + `X-FieldScope-User: <username>`）：适合第三方业务系统集成。
- **结构化元数据审计**：记录调用人、应用、协议、命中策略、注入参数、过滤行数、裁剪/脱敏字段与耗时，默认不落盘敏感响应明文。

---

## 快速开始

### 1. 安装后端依赖并运行测试

```bash
uv sync
uv run pytest -v
```

### 2. 构建前端并单服务一键启动（推荐）

```bash
# 构建 Vue 3 + Naive UI 管理台（产物输出至 web/dist，FastAPI 自动托管）
cd web && pnpm install && pnpm run build && cd ..

# 启动 FieldScope（默认 SQLite，监听 0.0.0.0:8000）
uv run fieldscope
```

启动后访问管理控制台：`http://localhost:8000`
- 默认初始管理员账号：`admin` / `admin123456`（生产环境请通过环境变量覆盖）
- Swagger API 文档：`http://localhost:8000/docs`

### 3. 前后端分离开发模式

```bash
# 终端 1：后端热重载
FIELDSCOPE_DEBUG=true uv run fieldscope

# 终端 2：Vue 3 + Naive UI 开发服务器（自动代理 /api、/gateway、/mcp）
cd web && pnpm run dev
```

---

## 常用环境变量

| 变量名 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `FIELDSCOPE_DATABASE_URL` | `sqlite+aiosqlite:///./fieldscope.db` | 数据库连接串（生产可切换 `postgresql+asyncpg://...`） |
| `FIELDSCOPE_SECRET_KEY` | 开发默认值 | JWT 签名与 OAuth State 签名密钥（生产必改） |
| `FIELDSCOPE_ENCRYPTION_KEY` | 开发默认值 | AES-256-GCM 主密钥，用于加密三方平台凭据与动态 Token（生产必改） |
| `FIELDSCOPE_BOOTSTRAP_ADMIN_USERNAME` | `admin` | 首次启动自动创建的超级管理员用户名 |
| `FIELDSCOPE_BOOTSTRAP_ADMIN_PASSWORD` | `admin123456` | 首次启动自动创建的超级管理员密码 |
| `FIELDSCOPE_HOST` / `FIELDSCOPE_PORT` | `0.0.0.0` / `8000` | 服务监听地址与端口 |

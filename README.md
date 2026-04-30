# ChatGPT / OpenAI OAuth Token 获取工具

基于本地账号密码、CloudMail 邮箱 OTP 和 OpenAI OAuth 流程的批量登录工具。

当前仓库的主入口是 `chatgpt_register_v2.py`，其实际职责是：

- 默认从 `accounts/accounts.txt` 读取账号密码
- 自动执行 OpenAI 登录
- 自动从 CloudMail 拉取邮箱验证码
- 获取 `access_token` / `refresh_token` / `id_token` / `session_token`
- 将结果写入 `tokens/`、`ak.txt`、`rk.txt`、`sub2api.json`

> 代码中仍保留“新账号注册引擎”，但当前 CLI 暴露的默认工作模式是“已有账号登录获取 token”。

## 项目现状

### 已实现能力

- 本地账号批量登录
- 按序号或邮箱筛选待处理账号
- CloudMail 邮件轮询获取 OTP
- OpenAI OAuth + PKCE 换取 Token
- Sentinel PoW Token 生成与提交
- Workspace 自动选择
- Token 多目标落盘
- `sub2api.json` 自动生成 / 更新
- 登录过程中遇到手机号补录时，支持控制台交互继续流程
- 失败账号写入 `failed_accounts.txt`

### 主流程

1. 读取本地账号文件
2. 检查出口 IP 地理位置
3. 初始化 OAuth 流程并获取 `oai-did`
4. 请求 Sentinel Token
5. 提交邮箱
6. 提交密码
7. 从 CloudMail 获取邮箱 OTP
8. 校验 OTP
9. 获取 / 选择 Workspace
10. 跟随 OAuth 重定向链
11. 用授权回调换取 Token
12. 输出到多个文件

## 项目结构

```text
.
├── chatgpt_register_v2.py   # CLI 入口：批量登录并获取 token
├── lib/
│   ├── clients.py           # HTTP / CloudMail / OAuth / TokenManager
│   ├── core.py              # RegistrationEngine 与登录/注册/OTP/手机号流程
│   ├── utils.py             # 常量、配置、Cookie/Token 辅助函数
│   └── __init__.py
├── config.example.json      # 配置模板
├── config.json              # 本地配置
├── accounts/
│   └── accounts.txt         # 默认本地账号文件
├── tokens/                  # 每个账号的 JSON token 文件
├── ak.txt                   # access_token 列表
├── rk.txt                   # refresh_token 列表
├── sub2api-tmpl.json        # sub2api 模板
└── sub2api.json             # sub2api 导出文件
```

## 关键模块说明

### `chatgpt_register_v2.py`

负责：

- 解析命令行参数
- 读取账号文件
- 选择账号范围
- 初始化 `CloudMailService`
- 初始化 `TokenManager`
- 串行或并发执行 `RegistrationEngine.run_login()`

支持的筛选参数：

- `--indexes`：按序号选择，例如 `5`、`1,3,7`、`2-6`、`-3`、`3-`
- `--emails`：按邮箱选择，多个邮箱用英文逗号分隔

### `lib/core.py`

核心流程编排：

- `RegistrationEngine.run_login()`：已有账号登录主流程
- `RegistrationEngine.run()`：新账号注册主流程
- `AuthOperations`：OAuth 初始化、`oai-did`、Sentinel
- `LoginOperations`：登录邮箱/密码提交、重触发 OTP
- `OTPOperations`：邮件验证码获取和校验
- `WorkspaceOperations`：Workspace 提取与选择
- `RedirectOperations`：OAuth 重定向跟随和回调恢复
- 手机号流程：当登录后跳到 `add-phone` / `phone-otp` 页面时，支持控制台输入手机号和短信验证码继续

### `lib/clients.py`

包含：

- `SentinelTokenGenerator`：纯 Python 生成 Sentinel requirements token
- `HTTPClient` / `OpenAIHTTPClient`
- `CloudMailService`
- `OAuthManager`
- `TokenManager`

`TokenManager.save_tokens()` 会同时处理：

- `ak.txt`
- `rk.txt`
- `tokens/<email>.json`
- `sub2api.json`
- 可选上传到外部 API（若配置 `upload_api_url`）

### `lib/utils.py`

提供：

- OpenAI 端点常量
- OAuth 常量
- 配置加载
- 随机密码与用户资料生成
- Cookie / session token 提取
- 日志格式化

## 依赖与运行环境

`pyproject.toml` 当前声明：

```toml
requires-python = ">=3.14"
```

依赖：

```bash
pip install curl-cffi requests
```

如果你使用仓库自带虚拟环境，也可以直接执行：

```bash
.venv/bin/python chatgpt_register_v2.py --indexes 5
```

## 配置说明

复制 `config.example.json` 为 `config.json` 后填写：

```json
{
  "cloudmail_admin_email": "admin@example.com",
  "cloudmail_admin_password": "your_password_here",
  "cloudmail_domains": [],
  "cloudmail_subdomain": "",
  "cloudmail_url": "",
  "outlook_mail_web_url": "https://ms.lqqq.cc/web",
  "timeout": 30,
  "proxy": "http://127.0.0.1:10808",
  "input_file": "accounts/accounts.txt",
  "output_file": "registered_accounts.txt",
  "failed_output_file": "failed_accounts.txt",
  "enable_oauth": true,
  "oauth_required": true,
  "oauth_issuer": "https://auth.openai.com",
  "oauth_client_id": "app_EMoamEEZ73f0CkXaXp7hrann",
  "oauth_redirect_uri": "http://localhost:1455/auth/callback",
  "ak_file": "ak.txt",
  "rk_file": "rk.txt",
  "token_json_dir": "tokens",
  "enable_sub2api_output": true,
  "sub2api_template_file": "sub2api-tmpl.json",
  "sub2api_output_file": "sub2api.json"
}
```

### 关键配置项

| 字段 | 说明 |
|---|---|
| `cloudmail_url` | CloudMail 服务地址 |
| `cloudmail_admin_email` | CloudMail 管理员邮箱 |
| `cloudmail_admin_password` | CloudMail 管理员密码 |
| `cloudmail_domains` | 生成邮箱可用域名列表 |
| `cloudmail_subdomain` | 可选子域名前缀 |
| `outlook_mail_web_url` | Outlook 邮箱验证码列表页完整前缀地址，程序会自动拼接 `账号----邮箱密码` |
| `proxy` | 请求代理 |
| `input_file` | 本地账号文件 |
| `output_file` | 成功账号输出文件 |
| `failed_output_file` | 失败账号输出文件 |
| `enable_oauth` | 是否要求获取 OAuth Token |
| `oauth_required` | OAuth 失败时是否判定整体失败 |
| `ak_file` | access token 输出文件 |
| `rk_file` | refresh token 输出文件 |
| `token_json_dir` | 单账号 JSON 文件目录 |
| `enable_sub2api_output` | 是否同步输出 `sub2api.json` |

## 账号文件格式

默认账号文件为 `accounts/accounts.txt`。

普通账号每行一个，支持三种格式：

```text
email@example.com----password123
email@example.com,password123
email@example.com password123
```

Outlook 账号单独使用 4 段格式：

```text
user@outlook.com----openai_password----mailbox_password----rt
```

字段含义：

- 第 1 段：OpenAI 登录邮箱
- 第 2 段：OpenAI 登录密码
- 第 3 段：Outlook 邮箱密码
- 第 4 段：预留 `rt`

注释行和空行会被忽略。

## 使用方法

### 处理全部账号

```bash
python3 chatgpt_register_v2.py
```

### 只处理第 5 条账号

```bash
python3 chatgpt_register_v2.py -i accounts/accounts.txt --indexes 5 -w 1
```

### 处理多个离散账号

```bash
python3 chatgpt_register_v2.py --indexes 1,3,8 -w 3
```

### 处理一个范围

```bash
python3 chatgpt_register_v2.py --indexes 2-6 -w 2
```

### 按邮箱筛选

```bash
python3 chatgpt_register_v2.py --emails a@example.com,b@example.com
```

### 限制实际处理数量

```bash
python3 chatgpt_register_v2.py --indexes 1-20 -n 5
```

### 禁用 OAuth

```bash
python3 chatgpt_register_v2.py --indexes 5 --no-oauth
```

## 命令行参数

| 参数 | 说明 |
|---|---|
| `-i, --input-file` | 指定账号文件，默认读取 `config.input_file` 或 `accounts/accounts.txt` |
| `-n, --num` | 处理数量上限，`0` 表示全部 |
| `-w, --workers` | 并发线程数 |
| `--indexes` | 按序号筛选账号 |
| `--emails` | 按邮箱筛选账号 |
| `--no-oauth` | 禁用 OAuth token 保存 |

## 输出文件

### `registered_accounts.txt`

成功账号记录，典型格式：

```text
email@example.com----password----oauth=ok
email@example.com----password----oauth=failed
```

### `failed_accounts.txt`

失败账号记录：

```text
email@example.com----password----failed=reason
```

### `ak.txt`

每行一个 `access_token`。

### `rk.txt`

每行一个 `refresh_token`。

### `tokens/<email>.json`

示例结构：

```json
{
  "type": "codex",
  "email": "user@example.com",
  "expired": "2026-05-07T15:44:04+08:00",
  "id_token": "",
  "account_id": "account_xxx",
  "access_token": "eyJ...",
  "last_refresh": "2026-04-27T15:44:04+08:00",
  "refresh_token": "def..."
}
```

### `sub2api.json`

若启用 `enable_sub2api_output`，程序会根据 `sub2api-tmpl.json` 自动追加或更新账号，输出格式适配 sub2api 导入。

## 登录流程细节

### 1. IP 地理位置检查

程序会访问：

```text
https://cloudflare.com/cdn-cgi/trace
```

若检测到 `CN` / `HK` / `MO` / `TW`，会直接视为不支持。

### 2. OAuth 与 PKCE

通过 `generate_oauth_url()` 生成：

- `state`
- `code_verifier`
- `code_challenge`
- 授权地址

之后通过回调地址向 `https://auth.openai.com/oauth/token` 交换 Token。

### 3. Sentinel

登录前会：

- 获取 `oai-did`
- 生成 Sentinel requirements token
- 请求 `https://sentinel.openai.com/backend-api/sentinel/req`
- 将返回 token 放入 `openai-sentinel-token` 请求头

### 4. OTP

验证码来源不是 IMAP，而是 CloudMail HTTP API：

- `/api/public/emailList`

程序会轮询邮件列表，提取 6 位验证码，并调用 OpenAI OTP 校验接口。

### 5. 手机号补录

如果 OAuth 收尾阶段跳转到：

- `about-you`
- `add-phone`
- `phone-verification`
- `phone-otp`

程序会进入控制台交互：

- 输入国家/地区
- 输入手机号
- 输入短信验证码

然后继续恢复 OAuth 回调链路。

这部分是当前流程里唯一明确依赖人工输入的分支。

## 关键 OpenAI 接口

以下端点可直接从代码中确认：

| 方法 | 路径 | 用途 |
|---|---|---|
| `POST` | `https://sentinel.openai.com/backend-api/sentinel/req` | Sentinel 校验 |
| `POST` | `https://auth.openai.com/api/accounts/authorize/continue` | 提交邮箱并进入登录/注册页面 |
| `POST` | `https://auth.openai.com/api/accounts/password/verify` | 登录密码校验 |
| `POST` | `https://auth.openai.com/api/accounts/user/register` | 新账号设置密码 |
| `GET` | `https://auth.openai.com/api/accounts/email-otp/send` | 触发邮箱验证码发送 |
| `POST` | `https://auth.openai.com/api/accounts/email-otp/validate` | 校验邮箱验证码 |
| `POST` | `https://auth.openai.com/api/accounts/create_account` | 创建账号资料 |
| `POST` | `https://auth.openai.com/api/accounts/workspace/select` | 选择 Workspace |
| `POST` | `https://auth.openai.com/oauth/token` | OAuth token 交换 |

## 并发建议

- `-w 1`：最稳
- `-w 2~3`：推荐
- `-w >5`：可能触发限流、OTP 混淆、CloudMail 竞争或 OpenAI 风控

虽然代码支持并发，但邮件 OTP 本身存在时序依赖，实际生产使用建议先小并发验证。

## 常见问题

### 1. `IP 地理位置不支持`

检查代理出口。代码会直接拦截 `CN/HK/MO/TW`。

### 2. 一直拿不到 OTP

优先检查：

- CloudMail 管理员配置是否正确
- `cloudmail_url` 是否可访问
- 目标邮箱域名是否真实可用
- OpenAI 邮件是否实际投递到 CloudMail

### 3. 登录成功但没有 token

检查：

- `enable_oauth`
- `oauth_required`
- 是否卡在手机号补录页面
- `tokens/` 是否有对应 JSON 文件

### 4. `--indexes` / `--emails` 同时用了

代码会直接报错，两者互斥。

### 5. 手机号页面卡住

该分支需要交互式终端。如果当前环境不是可交互 TTY，流程无法继续。

## 开发备注

### 实际能力与历史命名差异

仓库名称和部分注释仍强调“自动注册”，但从 CLI 入口看，当前最完整、最直接的使用方式是：

- 维护 `accounts.txt`
- 批量登录已有账号
- 获取和导出 OAuth Token

如果后续要让 README 与功能继续对齐，建议：

1. 将入口脚本名称与项目标题进一步统一
2. 将“注册模式”和“登录模式”拆成两个 CLI 子命令
3. 补充一份手机号交互流程的专门说明
4. 为 `sub2api.json` 增加字段说明与示例

## 许可证

仓库内未看到单独的许可证文件；如需开源发布，建议补充 `LICENSE`。

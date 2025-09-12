# VSV (Vulnerability Scanner and Verifier)

VSV 是一个基于 Claude Code 的自动化安全分析与验证框架，通过多级 Agent 协作完成代码库的安全漏洞扫描、分析与验证。

## 项目概述

VSV 由两个主要组件构成：
- **扫描引擎** (`scan.py`): 执行静态安全分析，识别潜在漏洞
- **验证引擎** (`verify.py`): 构建环境、启动服务并执行 PoC 以验证漏洞

两个引擎均基于 Claude Code SDK，通过编排多个专业子 Agent 协同工作，实现端到端的安全分析流程。

## 功能特点

- **多级 Agent 协作**: 通过 Task 工具链接多个专业 Agent，形成完整分析链
- **双路径分析**: 根据项目类型（网络服务/本地应用）自动选择分析路径
- **全面漏洞覆盖**: 支持 SSRF、SQL注入、XSS、目录遍历等网络漏洞，以及语言特定漏洞
- **自动化验证**: 生成并执行 PoC，迭代优化直至可靠复现
- **标准化输出**: 生成机器可读的 JSON 报告与人类友好的 Markdown 报告

## 系统要求

- Python 3.8+
- 依赖项：`claude-code-sdk`

## 安装

1. 克隆仓库
```bash
git clone https://github.com/d4rkd0g/vsv.git
cd vsv
```

2. 安装依赖
```bash
pip install -r requirements.txt
```

## 使用方法

### 扫描模式

扫描目标代码库以识别潜在安全漏洞：

```bash
python scan.py /path/to/target/project
```

扫描完成后，将在目标项目目录下生成：
- `verified_findings.json`: 已验证的漏洞列表
- `security-report.md`: 综合安全报告
- 各漏洞的详细分析报告

### 验证模式

验证特定漏洞报告的可利用性：

```bash
python verify.py /path/to/target/project /path/to/vulnerability_report.md
```

验证完成后，将在目标项目的 `verify_results/<vuln_id>/` 目录下生成：
- `verification.json`: 验证结果
- `verification.md`: 详细验证报告
- `reproduce.http` 或 `reproduce.sh`: 可复现的 PoC

## 工作流程

### 扫描流程

1. **项目分析**: 确定编程语言、业务领域、服务类型与架构
2. **分支决策**: 根据项目类型选择网络分析或本地服务分析
3. **攻击面映射**: 解析网络端点或本地接口
4. **漏洞检测**: 执行特定于项目类型的漏洞扫描
5. **深度分析**: 对每个潜在漏洞进行详细分析与验证
6. **报告生成**: 生成综合安全报告与详细漏洞分析

### 验证流程

1. **解析报告**: 提取漏洞ID、类型、文件位置等信息
2. **环境准备**: 分析项目依赖并构建环境
3. **服务启动**: 在本地启动目标服务
4. **PoC生成**: 基于漏洞报告生成测试用例
5. **PoC执行**: 执行测试并捕获结果
6. **迭代优化**: 根据执行结果优化PoC直至可靠复现
7. **结果输出**: 生成验证报告与复现脚本

## Agent 架构

### 扫描 Agent

- `static-analysis-scheduler`: 主编排 Agent，协调整个扫描流程
- `project-analysis-sub-agent`: 项目分析
- `network-analysis-sub-agent`: 网络服务分析
- `local-service-analyzer`: 本地服务分析
- `web-vulnerability-detector`: Web漏洞检测
- `local-vulnerability-detector`: 本地应用漏洞检测
- `vulnerability-analyzer`: 深度漏洞分析

### 验证 Agent

- `verify-orchestrator`: 主编排 Agent，协调整个验证流程
- `env-prep-sub-agent`: 环境准备
- `service-launcher-sub-agent`: 服务启动
- `poc-generator-sub-agent`: PoC生成
- `poc-executor-sub-agent`: PoC执行
- `poc-refiner-sub-agent`: PoC优化

## 安全注意事项

- 所有网络操作仅限本地 (127.0.0.1/localhost)
- 优先使用无害 PoC (如文件标记、回显)
- 避免破坏性操作
- 自动脱敏敏感信息

## TODO

- [ ] 拆分环境构建与启动流程
- [ ] 优化PoC生成与验证流程
- [ ] 增加MCP/Command
- [ ] 优化提示词
- [ ] ......

## 贡献指南

欢迎提交 Pull Request 或 Issue 以改进项目。特别欢迎以下方面的贡献：
- 新的漏洞检测模式
- 特定语言/框架的分析增强
- Agent 指令优化
- 输出格式扩展

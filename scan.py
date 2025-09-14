#!/usr/bin/env python3
"""Static Analysis Scheduler Agent for comprehensive security analysis."""

import anyio
import sys
import shutil
from pathlib import Path

from claude_code_sdk import (
    AssistantMessage,
    ClaudeCodeOptions,
    ResultMessage,
    TextBlock,
    query,
)


prompt = """ You are a Static Analysis Scheduler Agent responsible for orchestrating a comprehensive security analysis workflow.
  You coordinate six specialized sub-agents in a specific sequence to identify and analyze security vulnerabilities in
  codebases.


  Your workflow follows this exact sequence:

  1. **Project Analysis Sub-agent**: Always execute first. Analyze the project to determine:
     - Programming language(s) used
     - Business domain and functionality
     - Whether it's a local service or network-exposed service
     - Project structure and architecture

  2. **Branch Decision**: Based on project analysis results:
     - If network-exposed: Execute Network Analysis Sub-agent
     - If local-only: Execute Local Service Analysis Sub-agent

  3. **Network Analysis Sub-agent** (for network projects):
     - Parse all network endpoints (HTTP, gRPC, socket, etc.)
     - Document API interfaces and their functionality
     - Map the attack surface

  4. **Local Service Analysis Sub-agent** (for local projects):
     - Analyze user input handling mechanisms
     - Identify file loading, command execution, and system interaction functions
     - Document local interfaces and their capabilities

  5. **Vulnerability Detection** (based on project type):
     - **Web Vulnerability Detection Sub-agent** (for network projects): Analyze from network endpoint entries, line by
  line, for:
       - SSRF (Server-Side Request Forgery)
       - Directory traversal
       - SQL injection
       - XSS (Cross-Site Scripting)
       - CSRF (Cross-Site Request Forgery)
       - Authentication bypass
       - Authorization flaws
       - Input validation issues
       - Generate comprehensive vulnerability list
     - **Local Vulnerability Detection Sub-agent** (for local projects): Analyze for:
       - Template injection
       - Deserialization vulnerabilities
       - Language-specific issues:
         * Rust: Panic handling, unsafe code, memory safety
         * Go: Panic recovery, race conditions, buffer operations
         * C/C++: Buffer overflows, memory leaks, use-after-free
         * Other languages: Similar language-specific vulnerabilities
       - Generate comprehensive vulnerability list
     - **Standardized Output (JSON)**: After completing detection, produce a machine-readable array named `vulnerability_candidates`. Each item MUST contain at minimum:
       - `id`, `title`, `type`, `cwe` (if known), `severity` (Critical/High/Medium/Low), `confidence`
       - `file_path`, `start_line`, `end_line`, optional `start_col`, `end_col`
       - `evidence_snippet` (trimmed), optional `source_to_sink_trace`
       - `rationale` (why this is likely vulnerable), `detector` ("web"|"local")
       - `dedupe_key` (stable hash based on file path + code context)
       - `suggested_inputs_for_analyzer` (minimal context for deep analysis)

  6. **Verification Loop and Per‑Vulnerability Deep Analysis**:
     - For each item in `vulnerability_candidates`, invoke the `vulnerability-analyzer` sub-agent using the Task tool, passing the candidate JSON and minimal surrounding code context (e.g., ±30 lines or function body) as input.
     - The `vulnerability-analyzer` MUST:
       - Perform line-by-line tracing and root-cause analysis
       - Decide verification status: set `verified` boolean; if not verified, set `false_positive_reason`
       - Build a PoC or concrete reproduction steps (HTTP request/payload, CLI invocation, sample input, config)
       - Compute `cvss` (vector and score), assign `severity`, and map to `cwe`
       - Provide actionable remediation guidance
       - Write a per-vulnerability Markdown report with name pattern `<project>_<slugified-vuln-name>_<seq>.md`
       - Return an `analysis_result` JSON object including at least: `id`, `verified`, `false_positive_reason` (if any), `report_path`, `poc`, `cvss`, `severity`, `cwe`, `remediation_summary`, `confidence`, and `dedupe_key`
     - After the loop, discard false positives, de-duplicate by `dedupe_key` and file-range hash, and produce consolidated artifacts:
       - `verified_findings.json` (or SARIF) containing the final verified findings
       - `security-report.md` summarizing methodology, findings by severity, and prioritized remediation


  **Execution Rules:**
  - Follow the workflow sequence strictly
  - Each sub-agent must complete successfully before proceeding to next
  - Collect and pass results between agents appropriately
  - Handle errors gracefully and provide meaningful feedback
  - Ensure comprehensive coverage of all identified vulnerabilities
  - Generate final consolidated security report

  **Quality Assurance:**
  - Verify each analysis step completes thoroughly
  - Cross-validate findings between agents when possible
  - Ensure no false negatives in vulnerability detection
  - Provide actionable remediation guidance
  - Document all assumptions and limitations
"""

prompt += """

\nGLOBAL SCOPE & EXCLUSIONS (MUST FOLLOW)
- Do NOT report vulnerabilities from non-production paths: tests/, test/, __tests__/, examples/, example/, example(s)/, cookbook/, cookbooks/, docs/examples/, demo/, demos/, samples/.
- These paths MAY be analyzed to understand the overall architecture and business logic, but any issues found there must be marked informational and MUST NOT be added to vulnerability_candidates or final verified findings.
- If the ONLY occurrence of a pattern is under these excluded paths, treat it as non-actionable.

CLAUDE.MD REQUIREMENT
- Create or update a root file named 'claude.md' summarizing:
  1) Scope & Exclusions (copy the above list)
  2) Project Purpose (business objective in plain language)
  3) Business Logic & Main Data Flows (entrypoints, critical operations)
  4) Domain-specific False Positive Guardrails (e.g., SSRF: client/browser projects may accept intranet URLs legitimately; SSRF applies to server-initiated requests that cross trust boundaries)
  5) Assumptions & Non-goals
- Keep this document concise and actionable. Subsequent agents MUST consult claude.md to reduce false positives.
"""


def setup_target_environment(target_path: str) -> Path:
    """设置目标环境，复制agents文件夹到目标路径下的.agent文件夹"""
    target_dir = Path(target_path).resolve()
    
    if not target_dir.exists():
        print(f"错误: 目标路径不存在: {target_dir}")
        sys.exit(1)
    
    if not target_dir.is_dir():
        print(f"错误: 目标路径不是目录: {target_dir}")
        sys.exit(1)
    
    # 获取当前脚本所在目录
    script_dir = Path(__file__).parent
    agents_source = script_dir / "scan_agents"
    
    if not agents_source.exists():
        print(f"错误: scan_agents文件夹不存在: {agents_source}")
        sys.exit(1)
    
    # 目标.agent文件夹
    agents_target = target_dir / ".agents"
    
    try:
        # 如果目标文件夹已存在，先删除
        if agents_target.exists():
            shutil.rmtree(agents_target)
        
        # 复制agents文件夹到目标位置并重命名为.agent
        shutil.copytree(agents_source, agents_target)
        print(f"✓ 已复制agents文件夹到: {agents_target}")
        
    except Exception as e:
        print(f"错误: 复制agents文件夹失败: {e}")
        sys.exit(1)
    
    # Also ensure a claude.md exists with constraints and placeholders
    ensure_claude_md(target_dir)
    return target_dir


def ensure_claude_md(target_dir: Path) -> None:
    """Create claude.md in target repo root if it does not exist, with constraints and context placeholders."""
    claude_md = target_dir / "claude.md"
    if claude_md.exists():
        return
    content = """# Claude Context & Constraints

This file documents the analysis constraints and project context. All agents MUST consult this file to avoid false positives.

## Scope & Exclusions for Vulnerability Reporting
- Exclude from vulnerability reporting (but OK to read for understanding):
  - tests/, test/, __tests__/
  - examples/, example/, example(s)/
  - cookbook/, cookbooks/
  - docs/examples/
  - demo/, demos/, samples/

If an issue appears only in these paths, mark it informational and DO NOT include it in machine-readable outputs.

## Project Purpose (to be filled by analysis)
> Summarize the business/domain purpose of this project in 2-4 sentences.

## Business Logic & Main Data Flows (to be filled by analysis)
> List primary entrypoints (API routes/CLI), core operations, and sensitive flows.

## Domain-specific False Positive Guardrails
- SSRF nuance: Client/browser projects may allow users to input intranet URLs legitimately. SSRF applies to server-side code that initiates network requests to attacker-controlled targets crossing trust boundaries. Distinguish client vs server contexts.
- XSS nuance: Templating with trusted static inputs is not XSS; verify tainted data reaches sink without proper encoding.
- Auth/Authorization: Public endpoints by design are not auth bypass; validate against documented access model.

## Assumptions & Non-goals
- Keep local-only execution. Avoid contacting external hosts during analysis/verification.
"""
    try:
        claude_md.write_text(content, encoding="utf-8")
        print(f"✓ 已创建 {claude_md}")
    except Exception as e:
        print(f"警告: 创建 {claude_md} 失败: {e}")


async def FindVulnerabilities(target_directory: Path):
    """在指定目录执行安全漏洞分析"""
    print(f"=== 开始安全分析 ===")
    print(f"目标目录: {target_directory}")
    
    options = ClaudeCodeOptions(
        allowed_tools=["All"],
        permission_mode="bypassPermissions",  # 跳过所有权限验证
        can_use_tool=None,  # 不使用权限回调，直接允许所有工具
        cwd=str(target_directory),  # 设置工作目录为目标路径
        model="opus",  # 使用opus模型
    )

    async for message in query(
        prompt=prompt,
        options=options,
    ):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    print(f"Claude: {block.text}")
                elif hasattr(block, 'tool_use_id'):  # ToolUseBlock
                    print(f"🔧 工具调用: {block.name}")
                    if hasattr(block, 'input') and block.input:
                        # 显示关键参数
                        key_params = {}
                        for key, value in block.input.items():
                            if key in ['file_path', 'query', 'command', 'pattern', 'path', 'directory']:
                                key_params[key] = str(value)[:100] + ('...' if len(str(value)) > 100 else '')
                        if key_params:
                            print(f"   📋 参数: {key_params}")
                elif hasattr(block, 'tool_use_id') and hasattr(block, 'content'):  # ToolResultBlock
                    if hasattr(block, 'is_error') and block.is_error:
                        print(f"❌ 工具执行失败: {block.tool_use_id}")
                        if block.content:
                            error_msg = str(block.content)[:200] + ('...' if len(str(block.content)) > 200 else '')
                            print(f"   ⚠️  错误: {error_msg}")
                    else:
                        print(f"✅ 工具执行完成: {block.tool_use_id}")
                        # 显示结果摘要
                        if block.content:
                            content_str = str(block.content)
                            if len(content_str) > 150:
                                print(f"   📊 结果摘要: {content_str[:150]}...")
                elif hasattr(block, 'thinking'):  # ThinkingBlock
                    print(f"💭 思考中...")
        elif isinstance(message, ResultMessage):
            print(f"\n📈 分析完成统计:")
            print(f"   ⏱️  总用时: {message.duration_ms}ms (API: {message.duration_api_ms}ms)")
            print(f"   🔄 对话轮数: {message.num_turns}")
            if message.total_cost_usd and message.total_cost_usd > 0:
                print(f"   💰 成本: ${message.total_cost_usd:.4f}")
            if message.usage:
                print(f"   📊 Token使用: {message.usage}")
    print()


async def main():
    """主函数：解析命令行参数并执行安全分析"""
    if len(sys.argv) != 2:
        print("使用方法: python agc.py <目标路径>")
        print("示例: python agc.py /path/to/target/project")
        sys.exit(1)
    
    target_path = sys.argv[1]
    print(f"目标路径: {target_path}")
    
    # 设置目标环境
    target_directory = setup_target_environment(target_path)
    
    # 执行漏洞分析
    await FindVulnerabilities(target_directory)


if __name__ == "__main__":
    anyio.run(main)
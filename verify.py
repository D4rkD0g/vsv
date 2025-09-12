#!/usr/bin/env python3
"""
Verify Agent: Builds a test environment, launches the target service, generates and executes PoCs,
and iteratively refines them to produce a reliable verification for a given vulnerability report.

Usage:
  python verify_agent.py <target_repo_path> <vulnerability_report_path>

This script uses claude_code_sdk to run the 'verify-orchestrator' Claude Code agent defined in
verify_agent/agents/, merging those agent definitions into the target repo's .agents directory.
It streams tool use and assistant messages, and expects the agent to write artifacts under
<target_repo>/verify_results/<vuln_id>/
"""

import anyio
import sys
import shutil
import json
from pathlib import Path

from claude_code_sdk import (
    AssistantMessage,
    ClaudeCodeOptions,
    ResultMessage,
    TextBlock,
    query,
)


def merge_agents_to_target(target_path: str) -> Path:
    """Merge verify agents into target's .agents directory without deleting existing entries."""
    target_dir = Path(target_path).resolve()
    if not target_dir.exists() or not target_dir.is_dir():
        print(f"错误: 目标路径不可用: {target_dir}")
        sys.exit(1)

    script_dir = Path(__file__).parent
    agents_source = script_dir / "verify_agents"
    if not agents_source.exists():
        print(f"错误: verify_agent agents 不存在: {agents_source}")
        sys.exit(1)

    agents_target = target_dir / ".agents"
    agents_target.mkdir(parents=True, exist_ok=True)

    # Copy all .md files into .agents, overwriting same-named files if present
    for src in agents_source.glob("*.md"):
        dst = agents_target / src.name
        shutil.copy2(src, dst)
        print(f"✓ 已复制/更新 Agent 定义: {dst}")

    return target_dir


def read_report(report_path: str) -> str:
    p = Path(report_path).resolve()
    if not p.exists():
        print(f"错误: 漏洞报告不存在: {p}")
        sys.exit(1)
    try:
        return p.read_text(encoding="utf-8")
    except Exception as e:
        print(f"错误: 读取漏洞报告失败: {e}")
        sys.exit(1)


def build_prompt(report_text: str, report_path: str) -> str:
    return f"""
You are the Verify Orchestrator responsible for end-to-end vulnerability verification with reliable PoC execution.

Objective:
- In the target repository, prepare a safe, reproducible test environment
- Build/compile if required, then start the service locally
- Derive PoCs from the provided vulnerability report
- Execute PoCs against the local service (127.0.0.1 only), capture outputs, and refine iteratively until reliable
- Produce final verification artifacts: verification.md, verification.json, and reproducible PoC scripts/HTTP requests

Important:
- Use only local network targets (127.0.0.1/localhost). Do not contact external hosts.
- Prefer benign PoCs first (e.g., echo/file markers) before any risky actions. Avoid destructive operations.
- Persist all artifacts under verify_results/<vuln_id>/
- When suitable, delegate via Task to: env-prep-sub-agent, service-launcher-sub-agent, poc-generator-sub-agent, poc-executor-sub-agent, poc-refiner-sub-agent.

Inputs:
- Vulnerability report path: {report_path}
- Vulnerability report content (verbatim between <report> tags):
<report>
{report_text}
</report>

Deliverables:
- verification.json with fields: {{
    "id", "verified", "false_positive_reason", "type", "cwe", "cvss", "severity", "confidence",
    "file_path", "location": {{"start_line","end_line"}},
    "steps": [ ... executed steps ... ],
    "requests": [ ... executed HTTP requests (redacted secrets) ... ],
    "responses": [ ... summarized responses/logs ... ],
    "final_poc": {{ "type": "http|cli", ... details ... }},
    "report_path": "verify_results/<id>/verification.md"
}}
- verification.md explaining the environment, commands, PoCs, outcomes, and remediation validation
- reproducible PoC files: e.g., verify_results/<id>/reproduce.http or reproduce.sh

Process (strict):
1) Parse the report to extract id, type, file, lines, suspected routes or entrypoints
2) Analyze the repo to identify package manager, build/run scripts, env requirements
3) Build environment (env-prep-sub-agent). If multiple strategies exist, try safest first
4) Start local service (service-launcher-sub-agent). Prefer dev server or local-only mode on 127.0.0.1
5) Generate PoCs (poc-generator-sub-agent) from report details; serialize PoCs as JSON candidates
6) Execute PoCs (poc-executor-sub-agent) against local service; capture outputs; ensure safety
7) If not verified, refine PoCs (poc-refiner-sub-agent) and repeat 6 until verified or exhausted
8) Persist artifacts under verify_results/<id>/ and return final verification.json

Notes:
- If service type is not web, adapt PoC execution accordingly (CLI/IPC). Always keep artifacts consistent.
- Be explicit about ports, base URLs, env vars; default to http://127.0.0.1:3000 unless detected otherwise.
- Redact secrets in outputs; avoid exfiltration.
"""


async def VerifyVulnerability(target_directory: Path, report_path: str):
    print("=== 开始验证流程 ===")
    print(f"目标目录: {target_directory}")
    print(f"漏洞报告: {report_path}")

    report_text = read_report(report_path)
    prompt = build_prompt(report_text, report_path)

    options = ClaudeCodeOptions(
        allowed_tools=["All"],
        permission_mode="bypassPermissions",
        can_use_tool=None,
        cwd=str(target_directory),
        model="opus",
    )

    async for message in query(prompt=prompt, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    print(f"Claude: {block.text}")
                elif hasattr(block, 'tool_use_id'):
                    print(f"🔧 工具调用: {block.name}")
                    if hasattr(block, 'input') and block.input:
                        key_params = {}
                        for key, value in block.input.items():
                            if key in ['file_path', 'query', 'command', 'pattern', 'path', 'directory', 'url']:
                                key_params[key] = str(value)[:100] + ('...' if len(str(value)) > 100 else '')
                        if key_params:
                            print(f"   📋 参数: {key_params}")
                elif hasattr(block, 'tool_use_id') and hasattr(block, 'content'):
                    if hasattr(block, 'is_error') and block.is_error:
                        print(f"❌ 工具执行失败: {block.tool_use_id}")
                        if block.content:
                            error_msg = str(block.content)[:200] + ('...' if len(str(block.content)) > 200 else '')
                            print(f"   ⚠️  错误: {error_msg}")
                    else:
                        print(f"✅ 工具执行完成: {block.tool_use_id}")
                        if block.content:
                            content_str = str(block.content)
                            if len(content_str) > 200:
                                print(f"   📊 结果摘要: {content_str[:200]}...")
                elif hasattr(block, 'thinking'):
                    print("💭 思考中...")
        elif isinstance(message, ResultMessage):
            print("\n📈 验证流程统计:")
            print(f"   ⏱️  总用时: {message.duration_ms}ms (API: {message.duration_api_ms}ms)")
            print(f"   🔄 对话轮数: {message.num_turns}")
            if message.total_cost_usd and message.total_cost_usd > 0:
                print(f"   💰 成本: ${message.total_cost_usd:.4f}")
            if message.usage:
                print(f"   📊 Token使用: {message.usage}")
    print()


async def main():
    if len(sys.argv) != 3:
        print("使用方法: python verify_agent.py <目标仓库路径> <漏洞报告路径>")
        print("示例: python verify_agent.py /path/to/repo /path/to/vuln_report.md")
        sys.exit(1)

    target_path = sys.argv[1]
    report_path = sys.argv[2]

    target_directory = merge_agents_to_target(target_path)
    await VerifyVulnerability(target_directory, report_path)


if __name__ == "__main__":
    anyio.run(main)

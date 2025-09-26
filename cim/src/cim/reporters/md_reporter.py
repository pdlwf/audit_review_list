from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List


_SCENARIOS = {
    "数据模型 / 接口": [
        "同步更新调用方类型声明与序列化逻辑",
        "检查验证、Mock、合同测试",
        "回顾文档与示例代码"
    ],
    "路由调整": [
        "更新页面组件、导航、面包屑",
        "验证权限守卫、端到端测试",
        "刷新站点地图或爬虫配置"
    ],
    "环境变量 / 配置": [
        "核对默认值与本地/CI 注入",
        "更新文档与运维手册",
        "确认监控与告警引用"
    ],
    "文案 / i18n": [
        "同步各语言包",
        "检查 fallback 逻辑",
        "回归关键用户旅程"
    ],
    "事件 / 消息": [
        "核对生产者、消费者与重试策略",
        "更新 topic/queue 权限",
        "验证告警与仪表板"
    ],
}


def _top_directories(files: List[Dict[str, object]], top_n: int = 10) -> List[tuple[str, int]]:
    counter: Counter[str] = Counter()
    for node in files:
        path = node.get("path") or ""
        if not path:
            continue
        top = path.split("/", 1)[0]
        counter[top] += 1
    return counter.most_common(top_n)


def _subsystem_coupling(edges: List[Dict[str, object]]) -> Dict[str, Counter[str]]:
    coupling: Dict[str, Counter[str]] = defaultdict(Counter)
    for edge in edges:
        src = edge.get("from", "")
        dst = edge.get("to", "")
        if "/" not in src or "/" not in dst:
            continue
        src_top = src.split("/", 1)[0]
        dst_top = dst.split("/", 1)[0]
        if src_top == dst_top:
            continue
        coupling[src_top][dst_top] += 1
    return coupling


def build_markdown_report(output_path: Path, report: Dict[str, object]) -> None:
    nodes: List[Dict[str, object]] = report.get("nodes", [])  # type: ignore[assignment]
    edges: List[Dict[str, object]] = report.get("edges", [])  # type: ignore[assignment]
    files = [node for node in nodes if node.get("type") == "file"]
    symbols = [node for node in nodes if node.get("type") == "symbol"]
    hotspots = report.get("hotspots", [])[:5]

    directory_overview = _top_directories(files)
    coupling = _subsystem_coupling(edges)

    key_edges = sorted(
        edges,
        key=lambda e: (
            e.get("strength") == "strong",
            e.get("rule") is None,
            e.get("kind") == "import",
        ),
        reverse=True,
    )[:10]

    lines: List[str] = []
    lines.append("# 变更影响地图 (CIM)")
    lines.append("")
    lines.append(f"- 节点总数：{len(nodes)}，其中文件 {len(files)}，符号 {len(symbols)}")
    lines.append(f"- 边总数：{len(edges)}")
    lines.append("- 报告生成时间：" + str(report.get("generatedAt", "")))
    lines.append("")

    lines.append("## 项目地图")
    for directory, count in directory_overview:
        lines.append(f"- `{directory}/`：{count} 个文件")
    lines.append("")

    lines.append("## 子系统边界与耦合")
    if not coupling:
        lines.append("- 未发现跨子系统依赖")
    else:
        for src, targets in coupling.items():
            coupled = ", ".join(f"{dst}({count})" for dst, count in targets.most_common(5))
            lines.append(f"- `{src}` -> {coupled}")
    lines.append("")

    lines.append("## 关键链路")
    if not key_edges:
        lines.append("- 暂无关键链路数据")
    else:
        for edge in key_edges:
            note = f" ({edge['kind']})"
            if edge.get("rule"):
                note += f" - 规则:{edge['rule']}"
            lines.append(f"- `{edge['from']}` → `{edge['to']}`{note}")
    lines.append("")

    lines.append("## 热点文件")
    if not hotspots:
        lines.append("- 无 Git 热点或中心节点信息")
    else:
        for item in hotspots:
            desc = f"hotScore={item.get('hotScore', 0):.2f}, centrality={item.get('centrality', 0):.3f}"
            lines.append(f"- `{item['id']}`：{desc}")
    lines.append("")

    lines.append("## 常见改动场景提醒")
    for title, items in _SCENARIOS.items():
        lines.append(f"### {title}")
        for tip in items:
            lines.append(f"- {tip}")
        lines.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")


__all__ = ["build_markdown_report"]

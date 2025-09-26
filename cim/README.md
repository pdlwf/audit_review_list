# Change Impact Map (CIM)

CIM 提供跨语言的依赖图构建与变更影响分析，帮助开发者快速评估修改的波及范围。

## 安装

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ./cim
```

## 常用命令

- `cim build`：扫描仓库生成 `out/impact_map.*` 与交互图。
- `cim impact --target <path|symbol>`：查询变更影响，支持 `--depth`、`--format`。
- `cim open-graph`：打开 `impact_graph.html` 交互视图。

## 配置

根路径 `cim/cim.config.yaml` 控制 include/exclude、语言开关、规则加载等。自定义规则放在 `cim/rules/*.yaml`。

## 扩展

- 在 `src/parsers/` 添加新的语言解析器
- 在 `src/graph/rules_engine.py` 注册新的规则适配器
- 在 `src/reporters/` 扩展新的报告格式

详情参考代码内文档与测试案例。

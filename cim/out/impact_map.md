# 变更影响地图 (CIM)

- 节点总数：422，其中文件 11，符号 386
- 边总数：751
- 报告生成时间：2025-09-24T04:50:41Z

## 项目地图
- `basic_knowledge/`：11 个文件

## 子系统边界与耦合
- 未发现跨子系统依赖

## 关键链路
- `basic_knowledge/__init__.py` → `module:method_harvester` (import)
- `basic_knowledge/method_harvester/__init__.py` → `module:__future__` (import)
- `basic_knowledge/method_harvester/__init__.py` → `module:pathlib` (import)
- `basic_knowledge/method_harvester/__init__.py` → `module:typing` (import)
- `basic_knowledge/method_harvester/__init__.py` → `basic_knowledge/method_harvester/parser.py` (import)
- `basic_knowledge/method_harvester/__init__.py` → `basic_knowledge/method_harvester/registry.py` (import)
- `basic_knowledge/method_harvester/__init__.py` → `basic_knowledge/method_harvester/manifest.py` (import)
- `basic_knowledge/method_harvester/__init__.py` → `basic_knowledge/method_harvester/normalize.py` (import)
- `basic_knowledge/method_harvester/__init__.py` → `basic_knowledge/method_harvester/renderer.py` (import)
- `basic_knowledge/method_harvester/manifest.py` → `module:__future__` (import)

## 热点文件
- `basic_knowledge/method_harvester/parser.py`：hotScore=0.18, centrality=0.003
- `basic_knowledge/method_harvester/renderer.py`：hotScore=0.18, centrality=0.002
- `basic_knowledge/scripts/harvest_methods.py`：hotScore=0.18, centrality=0.002
- `basic_knowledge/method_harvester/normalize.py`：hotScore=0.09, centrality=0.003
- `basic_knowledge/method_harvester/manifest.py`：hotScore=0.09, centrality=0.002

## 常见改动场景提醒
### 数据模型 / 接口
- 同步更新调用方类型声明与序列化逻辑
- 检查验证、Mock、合同测试
- 回顾文档与示例代码

### 路由调整
- 更新页面组件、导航、面包屑
- 验证权限守卫、端到端测试
- 刷新站点地图或爬虫配置

### 环境变量 / 配置
- 核对默认值与本地/CI 注入
- 更新文档与运维手册
- 确认监控与告警引用

### 文案 / i18n
- 同步各语言包
- 检查 fallback 逻辑
- 回归关键用户旅程

### 事件 / 消息
- 核对生产者、消费者与重试策略
- 更新 topic/queue 权限
- 验证告警与仪表板

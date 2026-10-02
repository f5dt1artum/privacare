# PrivaCare

这是一个面向医疗数据隐私与合规的医疗数据隐私与合规平台。长期目标是提供敏感字段识别、去标识化、重标识风险度量、同意管理与用途约束、审计证据链、脱敏查询、差分隐私和联邦学习，把隐私合规沉淀为可复用平台。

仓库采用 Python，当前冻结基线只提供进程健康检查。后续能力必须通过独立题目逐步实现；每个题目都应定义可观察的公共行为、兼容边界和失败语义，不得依赖未公开内部 API。

## 启动

```bash
PYTHONPATH=src python3 -m privacare.server --host 127.0.0.1 --port 8080
```

服务默认监听 `127.0.0.1:8080`，可通过 `PRIVACARE_ADDR` 修改。`GET /healthz` 返回 JSON 健康状态。

## 接口

### `POST /v1/classify`

批量医疗记录敏感字段识别。请求体为 JSON 对象：

- `records`：非空数组，每项为一个医疗记录对象（可含嵌套对象与数组）。
- `schema`（可选）：对象，键为 JSON Pointer，值为类别或类别数组，仅对当前请求生效。

响应为 `{"results": [...]}`，按输入顺序给出每条记录的 `index` 与 `fields`。每个命中项只含 `path`（转义正确的 JSON Pointer，数组元素带下标）、`categories`（`direct_identifier`、`contact`、`clinical`、`financial`、`quasi_identifier`，固定顺序去重）与 `sources`（`schema` / `field_name` / `value`），不回显原始值；未命中的记录返回空 `fields`。

错误语义：非 `application/json` 返回 415 `unsupported_media_type`；JSON 解析失败返回 400 `invalid_json`；请求结构非法返回 422 `invalid_request`；schema 非法返回 422 `invalid_schema`；其他方法返回 405 `method_not_allowed`。任何校验失败都不返回部分分析结果。

### `POST /v1/deidentify`

批量医疗记录去标识化。请求体为 JSON 对象：

- `records`：非空数组，每项为一个医疗记录对象（可含嵌套对象与数组）。
- `schema`（可选）：与 `POST /v1/classify` 同义，仅对当前请求生效。
- `policy`（必需）：非空对象，键仅为五种敏感类别，值仅为 `keep`、`redact` 或 `drop`。未配置的类别按 `keep` 处理；同一叶子命中多个类别时按 `drop` > `redact` > `keep` 的优先级选择唯一动作。

处理时先按现有分类规则与本次 schema 找出叶子，再逐条复制后变换：`redact` 将叶子值替换为 `null`；`drop` 删除对象成员、对数组元素替换为 `null`（删除后保留可能变空的父容器）；`keep` 不修改。响应为 `{"results": [...]}`，按输入顺序给出每条记录的 `index`、变换后的 `record` 与 `transformations`；清单按 `path` 字典序排列，每项只含 `path`、最终 `action` 与按固定顺序去重的 `categories`，不回显原始值。进程内调用不会修改调用方传入的数据，重复处理相同输入结果一致。

错误语义：HTTP 层与 `POST /v1/classify` 一致；缺少 `policy` 返回 422 `invalid_request`；`policy` 不是对象、为空、含未知类别或动作非法返回 422 `invalid_policy`。任何校验失败都不返回部分结果。

### `POST /v1/reidentification-risk`

基于 k 匿名的重标识风险度量。请求体为 JSON 对象：

- `records`：与其他接口一致的非空医疗记录对象数组。
- `quasi_identifiers`：非空、不重复的 JSON Pointer 字符串数组，按顺序指定准标识字段。每个指针在每条记录上都必须解析到 JSON 标量（`null` 可参与分组）；缺失、越界或落到对象/数组时整个请求失败。
- `k`：不小于 2 的 JSON 整数（布尔值不接受）。

等价组由各准标识值的有序组合确定，字符串区分大小写，布尔值不与数字相等（`true ≠ 1`），JSON 数字按数值相等（`1 = 1.0`）。响应为 `{"summary": ..., "results": [...]}`：`summary` 给出 `k`、`record_count`、`equivalence_class_count`、`minimum_class_size`、`at_risk_records` 与 `at_risk_rate`；组大小小于 `k` 的记录计入风险。`results` 按输入顺序给出每条记录的 `index`、`class_size`、`risk_score`（即 `1/class_size`）与 `at_risk`。比例与分数均按十进制 5 入保留六位小数。响应不回显准标识值、分组键或原始记录；评估仅作用于当前请求，不保存数据、不修改输入，相同输入产生相同结果，仅改变输入顺序不改变各记录的组大小与风险结论。

错误语义：HTTP 层与 `POST /v1/classify` 一致；`quasi_identifiers` 不是合规数组、含重复项或非法 JSON Pointer，或任一指针未解析为标量时返回 422 `invalid_quasi_identifiers`；`k` 为布尔值、非整数或小于 2 时返回 422 `invalid_k`。任何校验失败都不返回部分结果；该路径的非 POST 方法返回 405 `method_not_allowed`，未知路径返回 404 `not_found`。

## 验证

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

当前基线刻意不包含同意管理与审计证据链的实现，以便后续任务从已冻结事实出发独立设计并验证这些能力。

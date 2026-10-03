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

### `POST /v1/pseudonymize`

请求级、无状态的确定性假名化，可在不保存任何映射的前提下保持跨记录关联。请求体为 JSON 对象：

- `records`：与其他接口一致的非空医疗记录对象数组。
- `fields`：非空、不重复的 JSON Pointer（RFC 6901）字符串数组，支持对象、数组及 `~0`、`~1` 转义。每个指针在每条记录上都必须解析为非空字符串叶子；缺失、数组越界、索引含前导零（`"0"` 本身除外）、`-`、目标为对象/数组/`null`/`true`/`false`/数字/空字符串时整个请求失败。
- `key_id`：非空密钥版本标识字符串。
- `secret`：无填充 base64url 字符串，解码后不少于 32 字节。
- `context`（可选）：非空字符串，省略或为 `null` 时采用固定默认值 `privacare.pseudonymize.v1`。

每个目标值替换为 `pv1.<key_id>.<token>`；`token` 为 43 个无填充 base64url 字符，是对 `key_id`、`context`、规范化路径（转义正确的 JSON Pointer）与原值以请求 `secret` 计算 HMAC-SHA256 后编码而得。同一 `secret`、`key_id`、`context`、规范化路径与原值组合始终得到相同假名，上述任一项变化都产生不同假名——同值同路径跨记录得到相同假名，同值不同路径得到不同假名。响应为 `{"results": [...]}`，按输入顺序给出每条记录的 `index`、变换后的 `record` 与 `transformations`；清单按 `path` 字典序排列，每项只含 `path` 与 `key_id`。非目标内容保持不变；响应及错误均不回显原值或 `secret`；进程内调用不修改输入，相同输入结果一致，请求之间不保存记录、密钥或映射。

错误语义：HTTP 层与 `POST /v1/classify` 一致；根对象或 `records` 非法返回 422 `invalid_request`；`fields` 缺失、类型错误、为空、重复、指针非法，或路径缺失、越界、索引含前导零、目标不是非空字符串叶子时返回 422 `invalid_fields`；`key_id` 或 `secret` 不合规返回 422 `invalid_key`；`context` 非法返回 422 `invalid_context`。任何校验失败都不返回部分结果；该路径的非 POST 方法返回 405 `method_not_allowed`，未知路径返回 404 `not_found`。

### `POST /v1/reidentification-risk`

基于 k 匿名的重标识风险度量。请求体为 JSON 对象：

- `records`：与其他接口一致的非空医疗记录对象数组。
- `quasi_identifiers`：非空、不重复的 JSON Pointer 字符串数组，按顺序指定准标识字段。每个指针在每条记录上都必须解析到 JSON 标量（`null` 可参与分组）；缺失、越界或落到对象/数组时整个请求失败。
- `k`：不小于 2 的 JSON 整数（布尔值不接受）。

等价组由各准标识值的有序组合确定，字符串区分大小写，布尔值不与数字相等（`true ≠ 1`），JSON 数字按数值相等（`1 = 1.0`）。响应为 `{"summary": ..., "results": [...]}`：`summary` 给出 `k`、`record_count`、`equivalence_class_count`、`minimum_class_size`、`at_risk_records` 与 `at_risk_rate`；组大小小于 `k` 的记录计入风险。`results` 按输入顺序给出每条记录的 `index`、`class_size`、`risk_score`（即 `1/class_size`）与 `at_risk`。比例与分数均按十进制 5 入保留六位小数。响应不回显准标识值、分组键或原始记录；评估仅作用于当前请求，不保存数据、不修改输入，相同输入产生相同结果，仅改变输入顺序不改变各记录的组大小与风险结论。

错误语义：HTTP 层与 `POST /v1/classify` 一致；`quasi_identifiers` 不是合规数组、含重复项或非法 JSON Pointer，或任一指针未解析为标量时返回 422 `invalid_quasi_identifiers`；`k` 为布尔值、非整数或小于 2 时返回 422 `invalid_k`。任何校验失败都不返回部分结果；该路径的非 POST 方法返回 405 `method_not_allowed`，未知路径返回 404 `not_found`。

### `POST /v1/consent/evaluate`

请求级同意与用途约束判定，不保存业务数据。请求体为 JSON 对象：

- `consents`：非空数组，每项为一个同意对象，字段为 `consent_id`（请求内唯一）、`subject_id`、`purposes`、`data_categories`、`recipients`（均为非空且不重复的字符串数组，类别仅限五种敏感类别）、`valid_from`、`valid_until`（带时区的 RFC 3339 时间，且结束时间必须晚于开始时间）与 `status`（`active` 或 `revoked`）。
- `accesses`：非空数组，每项为一个使用项，字段为 `subject_id`、`purpose`、`data_category`（五种类别之一）、`recipient` 与 `requested_at`（带时区的 RFC 3339 时间）。

使用项仅在主体、用途、类别和接收方被同一条 `active` 同意覆盖，且 `requested_at` 不早于 `valid_from` 并早于 `valid_until` 时允许；`revoked` 同意不授权。多条同意匹配时选择 `valid_from` 最晚者，相同再取 `consent_id` 字典序最小者。响应为 `{"results": [...]}`，按 `accesses` 顺序给出每项的 `index`、`allowed` 与 `reason`：允许时 `reason` 为 `consent_granted` 并带 `consent_id`，拒绝时为 `no_matching_consent` 且不带 `consent_id`。响应不回显输入，不修改输入，相同输入结果一致。

错误语义：HTTP 层与 `POST /v1/classify` 一致；根结构非法或数组缺失、为空时返回 422 `invalid_request`；同意缺字段、`consent_id` 重复、范围集合为空或重复、状态或类别非法、时间非法，或结束时间不晚于开始时间时返回 422 `invalid_consent`；使用项缺字段、类别或时间非法时返回 422 `invalid_access`。任何校验失败都不返回部分结果。

### `POST /v1/access/evaluate`

无状态的最小必要访问授权判定，仅处理当前请求，不保存数据，也不替代同意判定。请求体为 JSON 对象：

- `grants`：非空数组，每项为一个授权对象，字段为 `grant_id`（请求内唯一）、`principal_id`、`resource`、`purpose`（均为非空字符串），以及非空且不重复的 `operations`（仅限 `read`、`update`、`export`、`delete`）、`data_categories`（五种敏感类别）与 `field_scopes`（合法 RFC 6901 JSON Pointer）。
- `accesses`：非空数组，每项为一个访问对象，字段为 `principal_id`、`resource`、`purpose`、`operation`（非空字符串且为合法操作），以及非空且不重复的 `data_categories` 与 `fields`（合法 JSON Pointer）。

当某条授权的主体、资源、用途与访问相同，操作被授权包含，访问类别是授权类别的子集，且每个字段等于某个字段范围或按指针段为其后代时，该授权完整覆盖该访问；不得拼接多条授权。多条授权均覆盖时选择 `grant_id` 字典序最小者。响应为 `{"results": [...]}`，按访问顺序给出每项的 `index`、`allowed` 与 `reason`：允许时 `reason` 为 `access_granted` 并带 `grant_id`，拒绝时为 `no_matching_grant` 且不带 `grant_id`，响应不回显输入。

错误语义：HTTP 层与 `POST /v1/classify` 一致；根对象或 `grants`、`accesses` 结构非法、缺失或为空返回 422 `invalid_request`；授权字段缺失、`grant_id` 重复、值、集合、操作、类别或指针非法返回 422 `invalid_grant`；访问字段缺失、值、集合、操作、类别或指针非法返回 422 `invalid_access`。任何校验失败都不返回部分结果；该路径的非 POST 方法返回 405 `method_not_allowed`，未知路径返回 404 `not_found`。

### `POST /v1/audit/chain`

防篡改审计证据链建链，无状态；调用方可将上一批响应的 `final_hash` 作为下一批请求的 `anchor_hash` 衔接。请求体为 JSON 对象：

- `events`：非空数组，每项为一个事件对象，字段为 `event_id`（请求内唯一的非空字符串）、`occurred_at`（带时区的 RFC 3339 时间）、`actor_id`、`action`、`resource`、`purpose`（均为非空字符串）与 `outcome`（`allowed` 或 `denied`）；`details` 可省略，存在时须为 JSON 对象。其他扩展字段一并计入证据。
- `anchor_hash`（可选）：64 位十六进制字符串，省略时采用全零值。

事件按输入顺序处理，每步将前一哈希解码后的字节与事件按 RFC 8785 规范化所得 UTF-8 字节连接并计算 SHA-256。响应为 `{"anchor_hash": ..., "final_hash": ..., "evidence": [...]}`，其中 `anchor_hash` 为小写；`evidence` 每项仅含 `index`、`event_id`、`previous_hash` 与 `evidence_hash`。相同输入结果相同，不修改调用方数据，响应不回显事件值。

### `POST /v1/audit/verify`

验真建链接口所得证据链。请求体为 JSON 对象：

- `events`、`anchor_hash`：与 `POST /v1/audit/chain` 同义。
- `evidence`：与 `events` 等长的数组，每项含 `index`、`event_id`、`previous_hash` 与 `evidence_hash`。

依次复算并核对下标、事件标识、前序哈希与证据哈希。全部一致返回 `{"valid": true, "first_invalid_index": null}`；首次不一致返回 `{"valid": false, "first_invalid_index": <输入下标>}`。

错误语义：HTTP 层与 `POST /v1/classify` 一致；根对象非法或 `events` 缺失、为空返回 422 `invalid_request`；事件缺字段、类型或时间非法、`event_id` 重复返回 422 `invalid_audit_event`；锚点非法返回 422 `invalid_anchor`；`evidence` 非等长数组、条目缺字段或哈希格式非法返回 422 `invalid_evidence_chain`。任何校验失败都不返回部分证据，错误响应不含事件值。

### `POST /v1/lineage/trace`

请求级数据血缘追踪，无状态：数据集、流转与查询仅取自当前请求，不保存内容、不修改输入，相同输入结果一致。请求体为 JSON 对象：

- `datasets`：非空数组，每项含 `dataset_id`（请求内唯一的非空字符串）与非空、不重复且仅限五种敏感类别的 `data_categories`。
- `transfers`：数组（可为空），每项含 `transfer_id`（请求内唯一的非空字符串）、`from_dataset` 与 `to_dataset`（均须引用请求内已存在的数据集且互不相同）、带时区的 RFC 3339 `occurred_at`，以及非空、不重复的 `data_categories`；流转类别必须同时是源数据集与目标数据集类别的子集。
- `queries`：非空数组，每项含 `dataset_id`（已存在的数据集）、`direction`（仅 `upstream` 或 `downstream`）、起点数据集所含的非空不重复 `data_categories` 集合（须为起点类别的子集）、`max_depth`（1 至 20 的 JSON 整数，布尔值不接受），以及可选的带时区 RFC 3339 `as_of`。

追踪沿请求方向构成有向图：下游从起点沿 `from_dataset -> to_dataset` 前进，上游反向追溯。路径只经过包含全部查询类别、且 `occurred_at` 不晚于 `as_of` 的流转；省略 `as_of` 时使用全部流转。到达数据集以最短边数为距离，环路不会产生重复节点或无限遍历。响应为 `{"results": [...]}`，按查询顺序给出每项的 `index`、`dataset_id`、`direction` 与 `datasets`；`datasets` 含起点及 `max_depth` 内全部可达数据集，每项仅含 `dataset_id`、`distance`（最短边数，起点为 0）与 `transfer_path`（起点为空数组）。多条等长最短路径并存时取 `transfer_id` 序列字典序最小者；清单按 `distance`、再按 `dataset_id` 排序。

错误语义：HTTP 层与 `POST /v1/classify` 一致；根结构非法或 `datasets`、`queries` 缺失、为空、非数组，或 `transfers` 非数组时返回 422 `invalid_request`；数据集缺字段、`dataset_id` 为空或重复、类别集合为空、重复或非法返回 422 `invalid_dataset`；流转缺字段、字段为空、`transfer_id` 重复、端点相同或引用不存在、时间非法或类别集合非法（含类别不是两端数据集类别的子集）返回 422 `invalid_transfer`；查询缺字段、引用未知数据集、`direction` 非法、`max_depth` 越界或为布尔/非整数、`as_of` 非法，或类别集合为空、重复、非法、不是起点类别的子集时返回 422 `invalid_query`。任何校验失败都不返回部分结果或完整输入；该路径的非 POST 方法返回 405 `method_not_allowed`，未知路径返回 404 `not_found`。

## 验证

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

当前基线已包含审计证据链的建链与验真，以及请求级数据血缘追踪能力；后续题目应从已冻结事实出发独立设计并验证其余能力。

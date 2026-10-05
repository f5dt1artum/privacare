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

### `POST /v1/consent/timeline`

请求级同意生命周期重建，无状态：事件与查询仅取自当前请求，不保存内容、不修改输入，相同输入结果一致。请求体为 JSON 对象：

- `events`：非空数组，每项为一个生命周期事件，字段为 `event_id`（请求内唯一的非空字符串）、`consent_id`（非空字符串）、`version`（每个同意从 1 连续递增的正整数，布尔值不接受）、带时区的 RFC 3339 `occurred_at` 与 `type`（仅 `grant`、`amend`、`revoke`）。`grant` 只能是版本 1，且须给出非空 `subject_id`、`purposes`、`data_categories`、`recipients`、`valid_from`、`valid_until`；范围数组非空、不重复，类别仅限五种敏感类别，结束时间必须晚于开始时间。`amend` 完整替换范围与有效期并沿用 `subject_id`，不得携带 `subject_id`；`revoke` 不得携带上述任一字段。每个同意只能先 `grant`，再经若干 `amend`，最后至多一次 `revoke`；`version` 增大时 `occurred_at` 不得倒退，撤回后不能再有事件。
- `queries`：非空数组，每项含 `consent_id`（非空字符串）与带时区的 RFC 3339 `as_of`。

查询按 `consent_id` 纳入 `occurred_at` 不晚于 `as_of` 的事件并取最高版本重建状态：尚未授予时 `status` 为 `not_found` 且无快照；已撤回为 `revoked`；`as_of` 早于当前 `valid_from` 为 `pending`，不早于 `valid_until` 为 `expired`，其余为 `active`。响应为 `{"results": [...]}`，与 `queries` 同序；除 `not_found` 外每项含 `consent_id`、`status`、`version`、`last_event_id` 与当前完整同意快照 `snapshot`（含 `consent_id`、`subject_id`、排序后的 `purposes`、`data_categories`、`recipients` 及 `valid_from`、`valid_until`）。事件可任意排列，结果不受其输入顺序影响。

错误语义：HTTP 层与 `POST /v1/classify` 一致；根结构非法或 `events`、`queries` 缺失、为空、非数组时返回 422 `invalid_request`；事件字段、集合、时间、版本或序列非法返回 422 `invalid_consent_event`；查询非法返回 422 `invalid_query`。任何校验失败都不返回部分结果；该路径的非 POST 方法返回 405 `method_not_allowed`，未知路径返回 404 `not_found`。

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

### `POST /v1/encryption/encrypt`

请求级、无状态的字段级认证加密。请求体为 JSON 对象：

- `records`：与其他接口一致的非空医疗记录对象数组。
- `fields`：非空、不重复的非根 JSON Pointer（RFC 6901）字符串数组；每个指针在每条记录上都必须可解析（目标可为任意 JSON 值），且任意两个指针不得互为祖先或后代。
- `key_id`：非空密钥版本标识字符串。
- `secret`：无填充 base64url 字符串，解码后恰为 32 字节。
- `context`（可选）：非空字符串，省略或为 `null` 时采用固定默认值 `privacare.encryption.v1`。

每个目标值按 RFC 8785 规范化后以 A256GCM（AES-256-GCM）加密，替换为仅含 `alg`、`key_id`、`context`、`nonce`、`ciphertext` 的信封对象；`nonce` 为每次随机生成的 12 字节，`nonce` 与 `ciphertext`（附认证标签）均为无填充 base64url。认证数据绑定 `key_id`、`context` 与规范化路径，信封被移动到其他路径或在其他 `context` 下均无法通过认证。响应为 `{"results": [...]}`，按输入顺序给出每条记录的 `index`、变换后的 `record` 与按 `path` 字典序排列的 `transformations`（每项只含 `path` 与 `key_id`）。非目标内容保持不变；进程内调用不修改输入，请求之间不保存记录或密钥。

### `POST /v1/encryption/decrypt`

解密加密封口并恢复原值，无状态。请求体为 JSON 对象：

- `records`、`fields`：与 `POST /v1/encryption/encrypt` 同义；每个目标必须为合规信封。
- `keys`：非空对象，将密钥版本标识映射到无填充 base64url、解码后恰为 32 字节的 secret；信封引用的 `key_id` 必须在其中出现。

响应形状与加密一致，`transformations` 每项只含 `path` 与所用 `key_id`。信封结构或编码非法返回 422 `invalid_envelope`；认证失败（密钥错误、信封被移动或篡改）返回 422 `invalid_ciphertext`；`keys` 非法或缺少信封引用的密钥返回 422 `invalid_key`。

### `POST /v1/encryption/rotate`

密钥轮换：以旧密钥解密信封并以新密钥重新加密，保留各信封的 `context`，无状态且不修改输入。请求体为 JSON 对象：

- `records`、`fields`、`keys`：与 `POST /v1/encryption/decrypt` 同义，`keys` 提供旧密钥。
- `new_key_id`：非空新密钥版本标识字符串。
- `new_secret`：无填充 base64url、解码后恰为 32 字节的新密钥。

响应形状与加密一致，`transformations` 每项只含 `path`、`old_key_id` 与 `new_key_id`。轮换要么全部成功要么整体失败，绝不部分更新。

错误语义：HTTP 层与 `POST /v1/classify` 一致；根对象或 `records` 非法返回 422 `invalid_request`；`fields` 类型、重复、语法、重叠、路径缺失或解析非法返回 422 `invalid_fields`；`key_id`、`secret`、`keys`、缺少信封引用密钥或新密钥非法返回 422 `invalid_key`；`context` 非法返回 422 `invalid_context`；信封结构或编码非法返回 422 `invalid_envelope`；认证错误、信封被移动或篡改返回 422 `invalid_ciphertext`。任何校验失败都不返回部分结果；响应与错误均不回显密钥或受保护原值；该路径的非 POST 方法返回 405 `method_not_allowed`，未知路径返回 404 `not_found`。

### `POST /v1/query/aggregate`

带小群体保护的分组聚合查询，无状态且不修改输入。请求体为 JSON 对象：

- `records`：与其他接口一致的非空医疗记录对象数组。
- `group_by`：不重复的 RFC 6901 JSON Pointer 字符串数组，可为空以表示全局分组（单一组，键为空数组）。非空指针须在每条记录上解析为字符串、有限数字、布尔值或 `null`，不得指向对象或数组，也不得缺失、越界。
- `metrics`：非空数组，每个指标含请求内唯一的非空 `name`，以及仅限 `count`、`sum`、`average` 的 `operation`。`count` 不携带 `field`，统计组内记录数；`sum` 与 `average` 须携带非根 JSON Pointer `field`，且该字段在全部记录中均为有限 JSON 数字（布尔值不算数字，`NaN`/`Infinity` 不是合法 JSON 数字）。
- `minimum_group_size`：2 至 1000 的 JSON 整数（布尔值不接受）。

分组键按 `group_by` 顺序有序组合：不同 JSON 类型互不相等（`null ≠ false ≠ 0`），数字按数值相等（`1 = 1.0`），字符串区分大小写。组大小小于阈值的组整体隐藏，不计算也不返回其指标。`sum` 与 `average` 按十进制四舍五入保留六位小数。响应为 `{"groups": [...], "suppressed_group_count": N}`：每个可见组仅含 `key`（与 `group_by` 等长同序，全局分组为 `[]`）、`size` 与以指标名称为键的 `metrics`；`groups` 按各组首次出现顺序排列，`suppressed_group_count` 为被隐藏组的数量。被隐藏组不泄露键、大小、指标、记录下标或原始值；相同输入产生相同结果。

错误语义：HTTP 层与 `POST /v1/classify` 一致；根对象或 `records` 非法返回 422 `invalid_request`；`group_by` 类型错误、重复、指针语法非法、无法解析或解析到容器返回 422 `invalid_group_by`；指标名称、操作、字段组合非法、字段指针非法或字段不是有限数字返回 422 `invalid_metric`；阈值为布尔值、非整数或超出 2 至 1000 返回 422 `invalid_threshold`。任何校验失败都不返回部分结果；该路径的非 POST 方法返回 405 `method_not_allowed`，未知路径返回 404 `not_found`。

### `POST /v1/query/differential-aggregate`

面向公开分区的差分隐私聚合发布，无状态：不保存记录、密钥或预算，仅处理当前请求，不修改输入。请求体为 JSON 对象：

- `records`：与其他接口一致的非空医疗记录对象数组。
- `group_by`：不重复的 RFC 6901 JSON Pointer 字符串数组，可为空以表示全局分组。非空指针须在每条记录上解析为字符串、有限数字、布尔值或 `null`。
- `partitions`：非空的公开分区键数组。每个键与 `group_by` 等长，只含字符串、有限数字、布尔值或 `null`；不同 JSON 类型互不相等，数字按数值相等（`1 = 1.0`），重复键非法。
- `metrics`：非空数组，每个指标含请求内唯一的非空 `name`、仅限 `count` 或 `sum` 的 `operation`，以及大于 0 且不超过 10 的 `epsilon`。`sum` 另须携带非根 JSON Pointer `field`（在全部记录中均为有限 JSON 数字）与有限数值 `lower`、`upper`（`lower < upper`），求和前先把各值截断到该区间；`count` 不得携带 `field` 或边界。
- `budget`：对象，含非负有限数值 `limit` 与 `spent`。本次消耗为各指标 `epsilon` 之和，不随分区数增加；`spent + consumed` 超过 `limit` 时不得发布。
- `release_id`：非空发布标识字符串。
- `noise_secret`：无填充 base64url 字符串，解码后不少于 32 字节。

未匹配任何公开分区的记录被忽略；所有公开分区按输入顺序返回，包括真实计数为零的分区。`count` 敏感度为 1，`sum` 敏感度为 `upper - lower`，均加入尺度为 `敏感度 / epsilon` 的拉普拉斯噪声，负的加噪计数返回 0。噪声由 `noise_secret`、固定版本、`release_id`、带类型的分区键与指标名确定：相同发布重试结果一致，任一标识变化时使用独立噪声。响应为 `{"partitions": [...], "consumed": ..., "spent": ..., "remaining": ...}`：每个分区仅含 `key` 与以指标名称为键的 `metrics`，`spent` 为累计消耗，`remaining` 为剩余额度，数值均按十进制四舍五入保留六位小数。响应与错误均不回显记录或密钥。

错误语义：HTTP 层与 `POST /v1/classify` 一致；根对象或 `records` 非法返回 422 `invalid_request`；`group_by` 非法返回 422 `invalid_group_by`；`partitions` 非法返回 422 `invalid_partition`；指标或边界非法返回 422 `invalid_metric`；`budget`、`epsilon` 非法或余额不足返回 422 `invalid_privacy_budget`；`release_id` 或 `noise_secret` 非法返回 422 `invalid_noise_config`。任何校验失败都不返回部分结果；该路径的非 POST 方法返回 405 `method_not_allowed`，未知路径返回 404 `not_found`。

### `POST /v1/compliance/transfer/evaluate`

请求级跨境流转合规判定，无状态：规则与流转仅取自当前请求，不保存内容、不修改输入，相同输入结果一致。请求体为 JSON 对象：

- `rules`：非空数组，每项为一个规则对象，字段为 `rule_id`（请求内唯一的非空字符串）、`priority`（0 至 1000 的 JSON 整数，布尔值不接受）、`effect`（`allow` 或 `deny`）、`source_jurisdictions`、`destination_jurisdictions`、`purposes`、`legal_bases`（均为非空且不重复的字符串数组）、`data_categories`（非空、不重复且仅限五种敏感类别），以及带时区的 RFC 3339 `valid_from` 与 `valid_until`（结束时间必须晚于开始时间）。
- `transfers`：非空数组，每项为一个流转对象，字段为 `transfer_id`（请求内唯一的非空字符串）、互不相同的 `source_jurisdiction` 与 `destination_jurisdiction`、非空 `purpose` 与 `legal_basis`、非空不重复且仅限五种敏感类别的 `data_categories`，以及带时区的 RFC 3339 `requested_at`。

当某条规则的来源、目的、用途、法律基础集合分别命中流转取值，流转类别是规则类别的子集，且 `requested_at` 不早于 `valid_from` 并早于 `valid_until` 时，该规则匹配该流转；规则不得组合。每条流转选择 `priority` 最高的匹配规则，同优先级先选 `deny`，再取 `rule_id` 字典序最小者；无匹配规则时默认拒绝。响应为 `{"results": [...]}`，按流转顺序给出每项的 `index`、`transfer_id`、`allowed` 与 `reason`：命中 `allow` 时 `reason` 为 `transfer_allowed`，命中 `deny` 时为 `transfer_denied`，均带 `rule_id`；默认拒绝时为 `no_matching_rule` 且不带 `rule_id`。响应不回显规则、法律基础或类别。

错误语义：HTTP 层与 `POST /v1/classify` 一致；根结构非法或 `rules`、`transfers` 缺失、为空、非数组时返回 422 `invalid_request`；规则缺字段、`rule_id` 重复、`priority` 或 `effect` 非法、集合为空或重复、类别非法、时间非法或结束时间不晚于开始时间时返回 422 `invalid_rule`；流转缺字段、`transfer_id` 重复、来源与目的相同、类别或时间非法时返回 422 `invalid_transfer`。任何校验失败都不返回部分结果，错误响应不回显输入；该路径的非 POST 方法返回 405 `method_not_allowed`，未知路径返回 404 `not_found`。

### `POST /v1/subject-requests/process`

无状态的数据主体请求处理，请求级、不保存内容、不修改输入，相同输入结果一致。请求体为 JSON 对象：

- `records`：非空数组，每项为一个记录对象，字段为 `record_id`（请求内唯一的非空字符串）、`subject_id`（非空字符串）与对象 `data`。
- `requests`：非空数组，每项为一个主体请求对象，字段为 `request_id`（请求内唯一的非空字符串）、`subject_id`（非空字符串）、`type`（`export`、`correct` 或 `delete`）与布尔值 `verified`；仅 `correct` 必须携带非空 `changes` 数组，`export` 与 `delete` 不得携带 `changes`。`changes` 每项含 `record_id`、非根 RFC 6901 `path` 与任意 JSON `value`。

请求按输入顺序作用于记录副本。`verified` 为 `false` 时结果为 `{"status": "rejected", "reason": "identity_not_verified"}`，主体记录不变。已验证的 `export` 返回该主体按 `record_id` 排序的 `record_id` 与 `data`，无匹配时为空数组；`delete` 删除该主体全部记录，返回 `deleted_count` 与排序的 `record_ids`，重复删除返回零项；`correct` 的目标记录须当时存在并属于该主体，`path` 须指向 `data` 已有成员或数组元素，同一记录的路径不得重复或互为祖先，更正原子生效，变更位置按 `record_id`、`path` 排序返回。响应为 `{"results": [...], "records": [...]}`，`results` 与请求同序，`records` 为最终记录并保持原顺序。

错误语义：HTTP 层与 `POST /v1/classify` 一致；根结构或两个数组非法返回 422 `invalid_request`；记录字段非法或 `record_id` 重复返回 422 `invalid_record`；请求字段、类型、`verified`、`request_id` 唯一性非法，`export` 或 `delete` 携带 `changes`，或 `correct` 缺少 `changes` 返回 422 `invalid_subject_request`；更正项、指针、路径重叠、动态目标、主体归属或既有路径非法返回 422 `invalid_correction`。任何校验都不返回部分结果；该路径的非 POST 方法返回 405 `method_not_allowed`，未知路径返回 404 `not_found`。

### `POST /v1/federated/aggregate`

请求级联邦学习更新聚合，无状态：更新仅取自当前请求，不保存内容、不修改输入，相同输入结果一致。请求体为 JSON 对象：

- `round_id`：非空轮次标识字符串。
- `minimum_participants`：2 至 100 的 JSON 整数（布尔值不接受），发布聚合所需的最少更新数。
- `max_l2_norm`：正的有限数值（布尔值不接受），单条更新向量的 L2 范数上限。
- `updates`：非空数组，每项为一个参与方更新对象，含请求内唯一的非空 `participant_id`、1 至 1000000 的 JSON 整数 `sample_count`（布尔值不接受）与一维数组 `values`；向量长度为 1 至 4096，所有更新维度相同，元素只能是有限 JSON 数字（布尔值不算数字，`NaN`/`Infinity` 不是合法 JSON 数字）。

处理时先计算每个向量的 L2 范数：超过 `max_l2_norm` 的向量按 `max_l2_norm / 原范数` 的比例整体裁剪，恰好等于上限的不裁剪，零向量保持不变。再按 `sample_count` 对裁剪后的向量逐维加权平均。更新数少于 `minimum_participants` 时不得发布。成功响应仅含 `round_id`、`participant_count`、`total_sample_count`、`dimension`、`aggregate` 与 `clipped_participants`；聚合值按十进制四舍五入保留六位小数，负零规范为零，裁剪名单按 `participant_id` 字典序排列。改变更新顺序不改变聚合数值或裁剪名单；响应与错误均不回显单个更新内容。

错误语义：HTTP 层与 `POST /v1/classify` 一致；根对象或 `updates` 结构非法返回 422 `invalid_request`；`round_id`、`minimum_participants` 或 `max_l2_norm` 非法返回 422 `invalid_federated_config`；更新缺字段、更新项不是对象、`participant_id` 为空或重复、`sample_count` 非法、`values` 长度或维度非法、含非有限数字返回 422 `invalid_update`；未达到参与门槛返回 422 `insufficient_participants`。任何失败都不返回部分结果；该路径的非 POST 方法返回 405 `method_not_allowed`，未知路径返回 404 `not_found`。

## 验证

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

当前基线已包含审计证据链的建链与验真、请求级数据血缘追踪、字段级认证加密的加密、解密与轮换、带小群体保护的聚合查询、面向公开分区的差分隐私聚合发布，以及带 L2 裁剪与样本数加权平均的联邦学习更新聚合能力；后续题目应从已冻结事实出发独立设计并验证其余能力。

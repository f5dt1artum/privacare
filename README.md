# PrivaCare

这是一个面向医疗数据隐私与合规的医疗数据隐私与合规平台。长期目标是提供敏感字段识别、去标识化、重标识风险度量、同意管理与用途约束、审计证据链、脱敏查询、差分隐私和联邦学习，把隐私合规沉淀为可复用平台。

仓库采用 Python，当前冻结基线只提供进程健康检查。后续能力必须通过独立题目逐步实现；每个题目都应定义可观察的公共行为、兼容边界和失败语义，不得依赖未公开内部 API。

## 启动

```bash
PYTHONPATH=src python3 -m privacare.server --host 127.0.0.1 --port 8080
```

服务默认监听 `127.0.0.1:8080`，可通过 `PRIVACARE_ADDR` 修改。`GET /healthz` 返回 JSON 健康状态。

## 验证

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

当前基线刻意不包含去标识化、同意管理与审计证据链的实现，以便后续任务从已冻结事实出发独立设计并验证这些能力。

## 敏感字段识别

`POST /v1/classify` 对批量医疗记录做敏感字段识别。请求体为 JSON 对象：

- `records`：非空数组，每项为一个医疗记录对象（可嵌套对象与数组）。
- `schema`（可选）：JSON Pointer → 类别的映射，声明业务字段类别，仅对当前请求生效。

响应按输入顺序返回 `results`，每项含 `index` 与 `fields`；命中字段只给出
`path`（转义后的 JSON Pointer，数组含下标）、`categories` 与 `sources`，不回显原始值。
类别限定为 `direct_identifier`、`contact`、`clinical`、`financial`、`quasi_identifier`，
来源为 `schema`、`field_name`、`value`。输出按路径字典序、固定类别与来源顺序排列，同一输入始终得到相同 JSON。

错误语义：非 `application/json` 返回 415 `unsupported_media_type`；JSON 解析失败返回 400
`invalid_json`；请求结构非法返回 422 `invalid_request`；schema 非法返回 422
`invalid_schema`；其他方法访问该入口返回 405 `method_not_allowed`。

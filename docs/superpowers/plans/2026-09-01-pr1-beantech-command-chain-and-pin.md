# PR 1 — BeanTech 命令链路双轨 + PIN 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在不改变现有行为的前提下，为 BeanTech 平台增加一条经真车验证的命令链路（`generate-token` → `remote-ctrl/timely`），由 `beantech_encrypted_security_pin` 是否配置来切换。

**Architecture:** 双轨。未配置加密 PIN 时，命令仍走作者现有的 `POST /app-api/api/v1.0/vehicle/T5/sendCmd`，代码路径一行不变。配置后走 `POST /app-api/api/v3.0/vehicle/remote-ctrl/timely`；其中需要 PIN 的命令先调 `POST /app-api/api/v3.0/vehicle/security/generate-token` 取 `securityToken` 作为请求头，免 PIN 的三个命令（`FLASH`/`WHISTLE`/`WHISTLE_FLASH`）跳过该步。切换点收敛在 `gwm_client/china_client.py` 内，集成层只负责把 PIN 传下去。

**Tech Stack:** Python 3.13、`aiohttp`、pytest（`tests/python/client/`）、Home Assistant 自定义集成（`custom_components/gwm_ora/`）。

**Spec:** `docs/superpowers/specs/2026-09-01-beantech-port-to-ev-design.md`

## Global Constraints

- `gwm_client/` 不得 import Home Assistant。所有 HA 相关逻辑留在 `custom_components/gwm_ora/`。
- 未配置 `beantech_encrypted_security_pin` 时，BeanTech 的行为必须与改动前逐字节一致（同 URL、同 body、同 header）。现有 8 个命令**不得**新增 PIN 门控——那会让未配置的用户失去现有功能。
- 加密 PIN 是秘密，**不得**放进 `ChinaClientConfig`（其 docstring 声明为 "Stable non-secret limits"）。走 `ChinaClient.__init__` 的独立关键字参数。
- 不改动 NavInfo 与海外（EU/UK/IL/AU/NZ/RU）的任何路径。
- seqNo 格式固定为 `[0-9a-f]{32}[0-9]{4}`（常量 `_BEAN_TECH_SEQUENCE`），两条路径共用。
- 错误信息不得回显服务器响应体。
- 提交信息使用 Conventional Commits，作用域 `cn`。

## 已验证的协议事实（实现依据，勿改）

- `generate-token` 响应的 `data` 字段**直接是 JWT 字符串**，不是含 `securityToken` 的对象。
- timely 请求 body 形如 `{"commands":[{"controlType":"VEHICLE_UNLOCK"}],"sendType":0,"seqNo":"<32hex+4digits>","vin":"<VIN>"}`；无 cmdBody 的命令不带 `cmdBody` 键，也**不带** `isSaveConfig`（这与 T5 路径不同）。
- `securityToken` 作为**请求头**发送，头名就是 `securityToken`。
- 免 PIN 命令：`FLASH`、`WHISTLE`、`WHISTLE_FLASH`。其余命令必须先取 token。
- 结果轮询：timely 路径用 `GET /app-api/api/v3.0/vehicle/remote-ctrl/result?seqNo=<seqNo>&vin=<VIN>&msgType=remote`。
- `551210 远控正在执行中` 是前一条命令未收完时的正常响应，不是失败。
- `WHISTLE_FLASH` 的 controlType 来自 APK 字符串池推测，**尚未真车实测**，需在 PR 描述中声明。

---

## 文件结构

| 文件 | 职责 | 动作 |
|---|---|---|
| `gwm_client/commands.py` | BeanTech 动作白名单 | 修改（加 `horn_and_lights`） |
| `gwm_client/china_client.py` | 端点常量、命令构造、双轨切换、token 获取 | 修改（本 PR 主体） |
| `custom_components/gwm_ora/const.py` | 配置键常量 | 修改（加一个常量） |
| `custom_components/gwm_ora/config_flow.py` | 选项表单 | 修改（中国区新增字段） |
| `custom_components/gwm_ora/cloud_runtime.py` | 构造 `ChinaClient` | 修改（传入 PIN） |
| `custom_components/gwm_ora/entity.py` | 实体基类 | 修改（加 `security_pin_configured`） |
| `custom_components/gwm_ora/translations/en.json` | 英文文案 | 修改 |
| `custom_components/gwm_ora/translations/zh-Hans.json` | 中文文案 | 修改 |
| `tests/python/client/test_china_client.py` | 客户端层测试 | 修改（新增用例） |
| `tests/python/test_config_flow.py` | 选项流测试 | 修改（新增用例） |

---

## Task 0: 建立工作分支

**Files:**
- 无代码改动

- [ ] **Step 1: 在 GitHub 上 fork `moryoav/ha-gwm-ev` 到自己账号**

浏览器打开 https://github.com/moryoav/ha-gwm-ev 点 Fork。本步骤需人工完成。

- [ ] **Step 2: 添加 fork 为 remote 并建立分支**

```bash
cd /c/Users/Administrator/ha-gwm-ev
git remote add fork https://github.com/tyj365888/ha-gwm-ev.git
git remote -v
git checkout -b feat/beantech-command-chain-and-pin
```

- [ ] **Step 3: 确认基线测试通过**

Run: `cd /c/Users/Administrator/ha-gwm-ev && python -m pytest tests/python -q`
Expected: 全部通过。若失败，先解决环境问题再继续——不要在红色基线上开工。

- [ ] **Step 4: 提交 spec**

```bash
git add docs/superpowers/specs/2026-09-01-beantech-port-to-ev-design.md
git commit -m "docs(cn): add BeanTech port design spec"
```

---

## Task 1: `WHISTLE_FLASH`（闪灯+鸣笛）

最小的独立增量，两条路径都受益，不依赖双轨机制。

**Files:**
- Modify: `gwm_client/commands.py`（`BEANTECH_CHINA_VEHICLE_CONTROL_ACTIONS`）
- Modify: `gwm_client/china_client.py`（`_bean_tech_vehicle_control`，约 2501 行）
- Test: `tests/python/client/test_china_client.py`

**Interfaces:**
- Consumes: 无
- Produces: `_bean_tech_vehicle_control(command)` 现在对 `command.action == "horn_and_lights"` 返回 `("WHISTLE_FLASH", None)`

- [ ] **Step 1: 写失败的测试**

在 `tests/python/client/test_china_client.py` 末尾新增：

```python
async def test_beantech_horn_and_lights_maps_to_whistle_flash() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[{"code": "000000", "data": {}}],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    accepted = await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), "horn_and_lights")
    )
    assert accepted.command_id == BEAN_COMMAND_ID

    sends = [
        json.loads(request.body or b"null")
        for request in transport.calls
        if request.operation == "send_vehicle_control_command"
    ]
    assert sends[0]["commands"][0] == {
        "controlType": "WHISTLE_FLASH",
        "cmdBody": None,
    }
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python -m pytest tests/python/client/test_china_client.py::test_beantech_horn_and_lights_maps_to_whistle_flash -v`
Expected: FAIL，抛 `GwmRoutePolicyError`（`horn_and_lights` 不在白名单里）

- [ ] **Step 3: 加入白名单**

`gwm_client/commands.py`，在 `BEANTECH_CHINA_VEHICLE_CONTROL_ACTIONS` 集合中 `"flash_lights",` 之后加一行：

```python
        "horn_and_lights",
```

- [ ] **Step 4: 加入映射**

`gwm_client/china_client.py` 的 `_bean_tech_vehicle_control`，在 `flash_lights` 分支之后插入：

```python
    if command.action == "horn_and_lights":
        return "WHISTLE_FLASH", None
```

- [ ] **Step 5: 运行测试确认通过**

Run: `python -m pytest tests/python/client/test_china_client.py -v -k beantech`
Expected: 全部 PASS，包含既有的 `test_beantech_extended_controls_are_exact_and_unsupported_actions_fail_locally`

- [ ] **Step 6: 提交**

```bash
git add gwm_client/commands.py gwm_client/china_client.py tests/python/client/test_china_client.py
git commit -m "feat(cn): support BeanTech horn and lights via WHISTLE_FLASH"
```

---

## Task 2: 安全令牌获取（generate-token）

**Files:**
- Modify: `gwm_client/china_client.py`（端点常量约 104-117 行；`ChinaClient.__init__`；新增两个方法）
- Test: `tests/python/client/test_china_client.py`

**Interfaces:**
- Consumes: `_bean_tech_authenticated_headers`（约 1905 行，已存在）
- Produces:
  - `ChinaClient.__init__(..., bean_tech_security_password: str | None = None)`
  - `self._bean_tech_security_password: str | None`
  - `async def _generate_bean_tech_security_token(self, state, identifier, *, operation, deadline) -> str`

- [ ] **Step 1: 写失败的测试**

```python
async def test_beantech_security_token_is_read_from_plain_data_string() -> None:
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.sig"
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        generate_security_token=[{"code": "000000", "data": token}],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    resolved = await client._generate_bean_tech_security_token(
        client._required_session(operation="send_lock_command"),
        VehicleIdentifier(BEAN_VIN),
        operation="send_lock_command",
        deadline=_deadline(),
    )
    assert resolved == token

    request = next(
        call for call in transport.calls if call.operation == "generate_security_token"
    )
    assert request.url.endswith("/app-api/api/v3.0/vehicle/security/generate-token")
    assert json.loads(request.body or b"null") == {
        "securityPwd": "ENCRYPTED==",
        "eventType": 2,
        "version": 1,
    }
```

同时新增一个否定用例，确认 `data` 不是字符串时按 schema 错误处理而非崩溃：

```python
async def test_beantech_security_token_rejects_non_string_data() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        generate_security_token=[{"code": "000000", "data": {"securityToken": "x"}}],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    with pytest.raises(GwmSchemaError):
        await client._generate_bean_tech_security_token(
            client._required_session(operation="send_lock_command"),
            VehicleIdentifier(BEAN_VIN),
            operation="send_lock_command",
            deadline=_deadline(),
        )
```

注意：`_FakeTransport` 需支持新的 `generate_security_token` 操作，`_client()` 需支持 `bean_tech_security_password` 关键字，`_deadline()` 需存在。若测试辅助函数尚不支持，在本步一并扩展它们——它们都在同一测试文件顶部。

- [ ] **Step 2: 运行测试确认失败**

Run: `python -m pytest tests/python/client/test_china_client.py -v -k security_token`
Expected: FAIL，`AttributeError: 'ChinaClient' object has no attribute '_generate_bean_tech_security_token'`

- [ ] **Step 3: 增加端点常量**

`gwm_client/china_client.py`，在 `_BEAN_TECH_RESULT_URL`（约 117 行）之后插入：

```python
_BEAN_TECH_SECURITY_TOKEN_PATH = "/app-api/api/v3.0/vehicle/security/generate-token"
_BEAN_TECH_SECURITY_TOKEN_URL = _BEAN_TECH_BASE.rstrip("/") + _BEAN_TECH_SECURITY_TOKEN_PATH
_BEAN_TECH_TIMELY_PATH = "/app-api/api/v3.0/vehicle/remote-ctrl/timely"
_BEAN_TECH_TIMELY_URL = _BEAN_TECH_BASE.rstrip("/") + _BEAN_TECH_TIMELY_PATH
_BEAN_TECH_TIMELY_RESULT_PATH = "/app-api/api/v3.0/vehicle/remote-ctrl/result"
_BEAN_TECH_TIMELY_RESULT_URL = _BEAN_TECH_BASE.rstrip("/") + _BEAN_TECH_TIMELY_RESULT_PATH
_BEAN_TECH_PIN_EXEMPT_CONTROL_TYPES = frozenset({"FLASH", "WHISTLE", "WHISTLE_FLASH"})
```

- [ ] **Step 4: `ChinaClient.__init__` 接受加密 PIN**

在参数列表中 `authenticated_state` 之后加入 `bean_tech_security_password: str | None = None,`，并在方法体内保存：

```python
        if bean_tech_security_password is not None and (
            not isinstance(bean_tech_security_password, str)
            or not bean_tech_security_password.strip()
        ):
            raise GwmConfigurationError(operation="login")
        self._bean_tech_security_password = bean_tech_security_password
```

- [ ] **Step 5: 实现请求构造与令牌获取**

在 `_build_bean_tech_result_request`（约 1877 行）之后插入：

```python
    def _build_bean_tech_security_token_request(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
        *,
        operation: str,
        security_password: str,
    ) -> _ChinaTransportRequest:
        body = encode_dotnet_json(
            {
                "securityPwd": security_password,
                "eventType": 2,
                "version": 1,
            }
        )
        headers = self._bean_tech_authenticated_headers(
            state,
            identifier,
            operation=operation,
            method="POST",
            path=_BEAN_TECH_SECURITY_TOKEN_PATH,
            parameter="json=" + body,
        )
        headers["Content-Type"] = "application/json; charset=UTF-8"
        return _ChinaTransportRequest(
            operation="generate_security_token",
            service="bean_tech",
            method="POST",
            url=_BEAN_TECH_SECURITY_TOKEN_URL,
            headers=headers,
            body=body.encode("utf-8"),
        )

    async def _generate_bean_tech_security_token(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
        *,
        operation: str,
        deadline: _Deadline,
    ) -> str:
        password = self._bean_tech_security_password
        if password is None:
            raise GwmConfigurationError(operation=operation)
        response = await self._send_locked(
            self._build_bean_tech_security_token_request(
                state,
                identifier,
                operation=operation,
                security_password=password,
            ),
            deadline=deadline,
        )
        result = _decode_g_app_envelope(response, operation=operation)
        # 服务器把 JWT 直接放在 data 上，不是 {"securityToken": ...} 对象。
        token = _scalar_text(result)
        if token is None or not token or len(token) > 4096:
            raise GwmSchemaError(operation=operation)
        return token
```

- [ ] **Step 6: 运行测试确认通过**

Run: `python -m pytest tests/python/client/test_china_client.py -v -k security_token`
Expected: 两个用例均 PASS

- [ ] **Step 7: 运行全量测试确认无回归**

Run: `python -m pytest tests/python -q`
Expected: 全部通过

- [ ] **Step 8: 提交**

```bash
git add gwm_client/china_client.py tests/python/client/test_china_client.py
git commit -m "feat(cn): add BeanTech security token retrieval for remote control"
```

---

## Task 3: timely 命令请求构造

**Files:**
- Modify: `gwm_client/china_client.py`（新增 `_build_bean_tech_timely_request`）
- Test: `tests/python/client/test_china_client.py`

**Interfaces:**
- Consumes: Task 2 的 `_BEAN_TECH_TIMELY_PATH` / `_BEAN_TECH_TIMELY_URL`
- Produces: `_build_bean_tech_timely_request(state, identifier, *, sequence_number, operation, control_type, command_body, security_token) -> _ChinaTransportRequest`

- [ ] **Step 1: 写失败的测试**

```python
def test_beantech_timely_request_shape() -> None:
    client = _client(_FakeTransport())
    request = client._build_bean_tech_timely_request(
        _complete_state(),
        VehicleIdentifier(BEAN_VIN),
        sequence_number="0" * 32 + "9359",
        operation="send_lock_command",
        control_type="VEHICLE_UNLOCK",
        command_body=None,
        security_token="JWT",
    )
    assert request.url.endswith("/app-api/api/v3.0/vehicle/remote-ctrl/timely")
    assert request.headers["securityToken"] == "JWT"
    assert json.loads(request.body or b"null") == {
        "vin": BEAN_VIN,
        "seqNo": "0" * 32 + "9359",
        "sendType": 0,
        "commands": [{"controlType": "VEHICLE_UNLOCK"}],
    }


def test_beantech_timely_request_omits_security_token_header_when_exempt() -> None:
    client = _client(_FakeTransport())
    request = client._build_bean_tech_timely_request(
        _complete_state(),
        VehicleIdentifier(BEAN_VIN),
        sequence_number="0" * 32 + "9359",
        operation="send_vehicle_control_command",
        control_type="FLASH",
        command_body=None,
        security_token=None,
    )
    assert "securityToken" not in request.headers
```

注意断言中 body **没有** `isSaveConfig` 键、无 cmdBody 时**没有** `cmdBody` 键——这是 timely 与 T5 的实测差异。

- [ ] **Step 2: 运行测试确认失败**

Run: `python -m pytest tests/python/client/test_china_client.py -v -k timely_request`
Expected: FAIL，`AttributeError: ... '_build_bean_tech_timely_request'`

- [ ] **Step 3: 实现**

在 `_build_bean_tech_command_request`（约 1875 行结束处）之后插入：

```python
    def _build_bean_tech_timely_request(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
        *,
        sequence_number: str,
        operation: Literal[
            "send_lock_command",
            "send_close_windows_command",
            "send_vehicle_control_command",
        ],
        control_type: str,
        command_body: Mapping[str, object] | None,
        security_token: str | None,
    ) -> _ChinaTransportRequest:
        command: dict[str, object] = {"controlType": control_type}
        if command_body is not None:
            command["cmdBody"] = dict(command_body)
        body = encode_dotnet_json(
            {
                "vin": identifier.value,
                "seqNo": sequence_number,
                "sendType": 0,
                "commands": [command],
            }
        )
        headers = self._bean_tech_authenticated_headers(
            state,
            identifier,
            operation=operation,
            method="POST",
            path=_BEAN_TECH_TIMELY_PATH,
            parameter="json=" + body,
        )
        headers["Content-Type"] = "application/json; charset=UTF-8"
        if security_token is not None:
            headers["securityToken"] = security_token
        return _ChinaTransportRequest(
            operation=operation,
            service="bean_tech",
            method="POST",
            url=_BEAN_TECH_TIMELY_URL,
            headers=headers,
            body=body.encode("utf-8"),
        )
```

- [ ] **Step 4: 运行测试确认通过**

Run: `python -m pytest tests/python/client/test_china_client.py -v -k timely_request`
Expected: 两个用例 PASS

- [ ] **Step 5: 提交**

```bash
git add gwm_client/china_client.py tests/python/client/test_china_client.py
git commit -m "feat(cn): build BeanTech timely remote-control requests"
```

---

## Task 4: 车辆控制命令双轨切换

**Files:**
- Modify: `gwm_client/china_client.py`（`_send_vehicle_control_command_locked` 的 beantech 分支，约 1434-1459 行）
- Test: `tests/python/client/test_china_client.py`

**Interfaces:**
- Consumes: Task 2 的 `_generate_bean_tech_security_token` 与 `_BEAN_TECH_PIN_EXEMPT_CONTROL_TYPES`；Task 3 的 `_build_bean_tech_timely_request`
- Produces: 新私有方法 `_send_bean_tech_control(state, identifier, *, operation, control_type, command_body, deadline) -> RemoteCommandAcceptance`，供 Task 5 的锁车/关窗路径复用

- [ ] **Step 1: 写失败的测试**

```python
async def test_beantech_uses_t5_path_when_no_security_password() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[{"code": "000000", "data": {}}],
    )
    client = _client(transport)
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), "remote_stop")
    )
    sent = next(
        call for call in transport.calls if call.operation == "send_vehicle_control_command"
    )
    assert sent.url.endswith("/app-api/api/v1.0/vehicle/T5/sendCmd")
    assert not any(
        call.operation == "generate_security_token" for call in transport.calls
    )


async def test_beantech_uses_timely_path_with_token_when_password_configured() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        generate_security_token=[{"code": "000000", "data": "JWT"}],
        send_vehicle_control_command=[{"code": "000000", "data": {}}],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    await client.send_vehicle_control_command(
        ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), "remote_stop")
    )
    sent = next(
        call for call in transport.calls if call.operation == "send_vehicle_control_command"
    )
    assert sent.url.endswith("/app-api/api/v3.0/vehicle/remote-ctrl/timely")
    assert sent.headers["securityToken"] == "JWT"
    assert sum(
        1 for call in transport.calls if call.operation == "generate_security_token"
    ) == 1


async def test_beantech_pin_exempt_commands_skip_token_generation() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        send_vehicle_control_command=[
            {"code": "000000", "data": {}} for _ in range(3)
        ],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    for action in ("horn", "flash_lights", "horn_and_lights"):
        await client.send_vehicle_control_command(
            ChinaVehicleControlCommand(VehicleIdentifier(BEAN_VIN), action)  # type: ignore[arg-type]
        )
    assert not any(
        call.operation == "generate_security_token" for call in transport.calls
    )
    for call in transport.calls:
        if call.operation == "send_vehicle_control_command":
            assert call.url.endswith("/app-api/api/v3.0/vehicle/remote-ctrl/timely")
            assert "securityToken" not in call.headers
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python -m pytest tests/python/client/test_china_client.py -v -k "t5_path or timely_path or pin_exempt"`
Expected: 第一个 PASS（现状即 T5），后两个 FAIL（仍走 T5，且无 token 调用）

- [ ] **Step 3: 抽出共用的发送逻辑**

在 `_send_vehicle_control_command_locked` 之前插入新方法：

```python
    async def _send_bean_tech_control(
        self,
        state: ChinaAuthState,
        identifier: VehicleIdentifier,
        *,
        operation: Literal[
            "send_lock_command",
            "send_close_windows_command",
            "send_vehicle_control_command",
        ],
        control_type: str,
        command_body: Mapping[str, object] | None,
        deadline: _Deadline,
    ) -> RemoteCommandAcceptance:
        try:
            sequence_number = self._sequence_source()
        except Exception:
            raise GwmConfigurationError(operation=operation) from None
        if (
            not isinstance(sequence_number, str)
            or _BEAN_TECH_SEQUENCE.fullmatch(sequence_number) is None
        ):
            raise GwmConfigurationError(operation=operation)

        if self._bean_tech_security_password is None:
            request = self._build_bean_tech_command_request(
                state,
                identifier,
                sequence_number=sequence_number,
                operation=operation,
                control_type=control_type,
                command_body=command_body,
            )
        else:
            security_token: str | None = None
            if control_type not in _BEAN_TECH_PIN_EXEMPT_CONTROL_TYPES:
                security_token = await self._generate_bean_tech_security_token(
                    state,
                    identifier,
                    operation=operation,
                    deadline=deadline,
                )
            request = self._build_bean_tech_timely_request(
                state,
                identifier,
                sequence_number=sequence_number,
                operation=operation,
                control_type=control_type,
                command_body=command_body,
                security_token=security_token,
            )

        response = await self._send_locked(request, deadline=deadline)
        _decode_g_app_envelope(response, operation=operation)
        return RemoteCommandAcceptance(sequence_number)
```

- [ ] **Step 4: 改 beantech 分支调用新方法**

把 `_send_vehicle_control_command_locked` 中 1434-1459 行的 beantech 分支替换为：

```python
        if platform == "beantech":
            if command.action not in BEANTECH_CHINA_VEHICLE_CONTROL_ACTIONS:
                raise GwmRoutePolicyError(operation=operation)
            control_type, command_body = _bean_tech_vehicle_control(command)
            return await self._send_bean_tech_control(
                state,
                command.identifier,
                operation=operation,
                control_type=control_type,
                command_body=command_body,
                deadline=deadline,
            )
```

- [ ] **Step 5: 运行测试确认通过**

Run: `python -m pytest tests/python/client/test_china_client.py -v -k "t5_path or timely_path or pin_exempt"`
Expected: 三个用例全部 PASS

- [ ] **Step 6: 运行全量测试确认无回归**

Run: `python -m pytest tests/python -q`
Expected: 全部通过。既有的 `test_beantech_extended_controls_are_exact_and_unsupported_actions_fail_locally` 必须仍然通过——它没配 PIN，应继续走 T5。

- [ ] **Step 7: 提交**

```bash
git add gwm_client/china_client.py tests/python/client/test_china_client.py
git commit -m "feat(cn): route BeanTech vehicle controls through timely when PIN configured"
```

---

## Task 5: 锁车与关窗路径双轨

**Files:**
- Modify: `gwm_client/china_client.py`（`send_lock_command` / `send_close_windows_command` 的 beantech 分支，约 1340-1370 与 1420 行附近）
- Test: `tests/python/client/test_china_client.py`

**Interfaces:**
- Consumes: Task 4 的 `_send_bean_tech_control`
- Produces: 无新接口

- [ ] **Step 1: 写失败的测试**

```python
async def test_beantech_lock_and_windows_use_timely_with_token() -> None:
    transport = _FakeTransport(
        acquire_vehicles=[FIXTURE["responses"]["discovery"]],
        generate_security_token=[
            {"code": "000000", "data": "JWT"} for _ in range(3)
        ],
        send_lock_command=[{"code": "000000", "data": {}} for _ in range(2)],
        send_close_windows_command=[{"code": "000000", "data": {}}],
    )
    client = _client(transport, bean_tech_security_password="ENCRYPTED==")
    assert isinstance(
        await client.authenticate(_credentials(), state=_complete_state()),
        ChinaAuthenticated,
    )
    identifier = VehicleIdentifier(BEAN_VIN)
    await client.send_lock_command(DoorLockCommand(identifier, lock=False))
    await client.send_lock_command(DoorLockCommand(identifier, lock=True))
    await client.send_close_windows_command(CloseWindowsCommand(identifier))

    bodies = [
        json.loads(call.body or b"null")
        for call in transport.calls
        if call.operation in {"send_lock_command", "send_close_windows_command"}
    ]
    assert [body["commands"][0] for body in bodies] == [
        {"controlType": "VEHICLE_UNLOCK"},
        {"controlType": "VEHICLE_LOCK"},
        {
            "controlType": "WINDOW_CLOSE",
            "cmdBody": {
                "leftFront": 0,
                "leftBack": 0,
                "rightFront": 0,
                "rightBack": 0,
            },
        },
    ]
    assert sum(
        1 for call in transport.calls if call.operation == "generate_security_token"
    ) == 3
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python -m pytest tests/python/client/test_china_client.py -v -k lock_and_windows_use_timely`
Expected: FAIL，请求仍打到 T5、无 token 调用

- [ ] **Step 3: 改锁车与关窗的 beantech 分支**

定位这两处方法中构造 `_build_bean_tech_command_request` 的 beantech 分支（结构与 Task 4 改前一致：取 `sequence_number` → 构造请求 → `_send_locked` → `_decode_g_app_envelope` → 返回 `RemoteCommandAcceptance`），整段替换为：

```python
            control_type, command_body = _bean_tech_lock_window_control(command_code)
            return await self._send_bean_tech_control(
                state,
                command.identifier,
                operation=operation,
                control_type=control_type,
                command_body=command_body,
                deadline=deadline,
            )
```

其中 `command_code` 沿用该方法原有的取值逻辑（解锁 1、闭锁 2、关窗 3）。

- [ ] **Step 4: 运行测试确认通过**

Run: `python -m pytest tests/python/client/test_china_client.py -v -k lock_and_windows_use_timely`
Expected: PASS

- [ ] **Step 5: 运行全量测试确认无回归**

Run: `python -m pytest tests/python -q`
Expected: 全部通过。既有的 `test_beantech_lock_close_windows_and_legacy_result_are_isolated` 必须仍通过。

- [ ] **Step 6: 提交**

```bash
git add gwm_client/china_client.py tests/python/client/test_china_client.py
git commit -m "feat(cn): route BeanTech lock and window commands through timely"
```

---

## Task 6: 结果轮询双轨

**Files:**
- Modify: `gwm_client/china_client.py`（`_build_bean_tech_result_request`，约 1877 行）
- Test: `tests/python/client/test_china_client.py`

**Interfaces:**
- Consumes: Task 2 的 `_BEAN_TECH_TIMELY_RESULT_PATH` / `_BEAN_TECH_TIMELY_RESULT_URL`
- Produces: `_build_bean_tech_result_request` 在配置 PIN 时改用 v3.0 结果端点

- [ ] **Step 1: 写失败的测试**

```python
def test_beantech_result_request_uses_v3_endpoint_when_password_configured() -> None:
    client = _client(_FakeTransport(), bean_tech_security_password="ENCRYPTED==")
    request = client._build_bean_tech_result_request(
        _complete_state(),
        VehicleIdentifier(BEAN_VIN),
        "0" * 32 + "9359",
    )
    assert "/app-api/api/v3.0/vehicle/remote-ctrl/result" in request.url
    assert "msgType=remote" in request.url
    assert BEAN_VIN in request.url


def test_beantech_result_request_keeps_t5_endpoint_without_password() -> None:
    client = _client(_FakeTransport())
    request = client._build_bean_tech_result_request(
        _complete_state(),
        VehicleIdentifier(BEAN_VIN),
        "0" * 32 + "9359",
    )
    assert request.url.startswith(
        "https://gw-app-gateway.gwmapp-h.com/app-api/api/v1.0/vehicle/getRemoteCtrlResultT5"
    )
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python -m pytest tests/python/client/test_china_client.py -v -k result_request`
Expected: 第一个 FAIL，第二个 PASS

- [ ] **Step 3: 实现分支**

把 `_build_bean_tech_result_request` 方法体改为：

```python
        operation: Literal["get_remote_command_result"] = "get_remote_command_result"
        encoded_sequence = quote(command_id, safe="", encoding="utf-8", errors="strict")
        if self._bean_tech_security_password is None:
            headers = self._bean_tech_authenticated_headers(
                state,
                identifier,
                operation=operation,
                method="GET",
                path=_BEAN_TECH_RESULT_PATH,
                parameter="seqno=" + command_id,
            )
            return _ChinaTransportRequest(
                operation=operation,
                service="bean_tech",
                method="GET",
                url=_BEAN_TECH_RESULT_URL + "?seqNo=" + encoded_sequence,
                headers=headers,
                body=None,
            )

        encoded_vin = quote(identifier.value, safe="", encoding="utf-8", errors="strict")
        query = "seqNo=" + encoded_sequence + "&vin=" + encoded_vin + "&msgType=remote"
        headers = self._bean_tech_authenticated_headers(
            state,
            identifier,
            operation=operation,
            method="GET",
            path=_BEAN_TECH_TIMELY_RESULT_PATH,
            parameter=query,
        )
        return _ChinaTransportRequest(
            operation=operation,
            service="bean_tech",
            method="GET",
            url=_BEAN_TECH_TIMELY_RESULT_URL + "?" + query,
            headers=headers,
            body=None,
        )
```

- [ ] **Step 4: 运行测试确认通过**

Run: `python -m pytest tests/python/client/test_china_client.py -v -k result_request`
Expected: 两个用例 PASS

- [ ] **Step 5: 运行全量测试确认无回归**

Run: `python -m pytest tests/python -q`
Expected: 全部通过

- [ ] **Step 6: 提交**

```bash
git add gwm_client/china_client.py tests/python/client/test_china_client.py
git commit -m "feat(cn): poll BeanTech command results from the v3 endpoint when PIN configured"
```

---

## Task 7: 集成层配置项 `beantech_encrypted_security_pin`

**Files:**
- Modify: `custom_components/gwm_ora/const.py`
- Modify: `custom_components/gwm_ora/config_flow.py`（选项表单，约 190-223 行）
- Modify: `custom_components/gwm_ora/translations/en.json`
- Modify: `custom_components/gwm_ora/translations/zh-Hans.json`
- Test: `tests/python/test_config_flow.py`

**Interfaces:**
- Consumes: 无
- Produces: `CONF_BEANTECH_ENCRYPTED_SECURITY_PIN = "beantech_encrypted_security_pin"`，选项值为字符串或缺省

- [ ] **Step 1: 写失败的测试**

在 `tests/python/test_config_flow.py` 中新增：

```python
async def test_china_options_expose_beantech_encrypted_security_pin(hass) -> None:
    entry = _china_entry(hass)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    schema_keys = {str(key) for key in result["data_schema"].schema}
    assert "beantech_encrypted_security_pin" in schema_keys
    assert "security_pin" not in schema_keys


async def test_non_china_options_hide_beantech_encrypted_security_pin(hass) -> None:
    entry = _eu_entry(hass)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    schema_keys = {str(key) for key in result["data_schema"].schema}
    assert "beantech_encrypted_security_pin" not in schema_keys
```

`_china_entry` / `_eu_entry` 为该测试文件已有的辅助函数；若命名不同，沿用文件内既有的建条目辅助函数。

- [ ] **Step 2: 运行测试确认失败**

Run: `python -m pytest tests/python/test_config_flow.py -v -k beantech_encrypted`
Expected: FAIL，schema 中没有该键

- [ ] **Step 3: 增加常量**

`custom_components/gwm_ora/const.py`，在 `CONF_SECURITY_PIN` 之后加一行：

```python
CONF_BEANTECH_ENCRYPTED_SECURITY_PIN = "beantech_encrypted_security_pin"
```

- [ ] **Step 4: 加入选项表单**

`config_flow.py` 中现有逻辑是 `if region != REGION_CHINA:` 才加入 `CONF_SECURITY_PIN`。在该判断处补上 else 分支：

```python
        if region != REGION_CHINA:
            fields[
                vol.Optional(
                    CONF_SECURITY_PIN,
                    description={"suggested_value": options.get(CONF_SECURITY_PIN, "")},
                )
            ] = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))
        else:
            fields[
                vol.Optional(
                    CONF_BEANTECH_ENCRYPTED_SECURITY_PIN,
                    description={
                        "suggested_value": options.get(
                            CONF_BEANTECH_ENCRYPTED_SECURITY_PIN, ""
                        )
                    },
                )
            ] = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))
```

沿用该文件中 `CONF_SECURITY_PIN` 原有的 selector 写法；若原写法不是 `TextSelector`，照抄原写法即可，关键是键名与 Optional 语义。

- [ ] **Step 5: 增加英文文案**

`translations/en.json` 的 `options.step.init.data` 与 `data_description` 中加入：

```json
"beantech_encrypted_security_pin": "BeanTech encrypted security PIN"
```

```json
"beantech_encrypted_security_pin": "Mainland China BeanTech vehicles only. Paste the encrypted value produced by the app, not your PIN digits. Leave empty to keep the existing command path."
```

- [ ] **Step 6: 增加中文文案**

`translations/zh-Hans.json` 对应位置加入：

```json
"beantech_encrypted_security_pin": "BeanTech 安全 PIN 加密值"
```

```json
"beantech_encrypted_security_pin": "仅中国大陆 BeanTech 车辆。填写 App 加密后的结果，不是 PIN 数字本身。留空则维持原有命令路径。"
```

- [ ] **Step 7: 运行测试确认通过**

Run: `python -m pytest tests/python/test_config_flow.py -v -k beantech_encrypted`
Expected: 两个用例 PASS

- [ ] **Step 8: 提交**

```bash
git add custom_components/gwm_ora/const.py custom_components/gwm_ora/config_flow.py custom_components/gwm_ora/translations/en.json custom_components/gwm_ora/translations/zh-Hans.json tests/python/test_config_flow.py
git commit -m "feat(cn): add BeanTech encrypted security PIN option"
```

---

## Task 8: 把 PIN 接到客户端并暴露给实体

**Files:**
- Modify: `custom_components/gwm_ora/cloud_runtime.py`（`ChinaClient(...)` 构造处，约 453 行）
- Modify: `custom_components/gwm_ora/entity.py`
- Test: `tests/python/test_cloud_entities.py`

**Interfaces:**
- Consumes: Task 2 的 `ChinaClient(..., bean_tech_security_password=...)`；Task 7 的 `CONF_BEANTECH_ENCRYPTED_SECURITY_PIN`
- Produces: `GwmOraEntity.security_pin_configured -> bool`，供 PR 3 / PR 4 的新实体做 `available` 门控

- [ ] **Step 1: 写失败的测试**

```python
def test_security_pin_configured_reflects_option(hass) -> None:
    entity = _beantech_entity(hass, options={})
    assert entity.security_pin_configured is False

    entity = _beantech_entity(hass, options={"beantech_encrypted_security_pin": "X=="})
    assert entity.security_pin_configured is True

    entity = _beantech_entity(hass, options={"beantech_encrypted_security_pin": "   "})
    assert entity.security_pin_configured is False
```

`_beantech_entity` 为该测试文件已有的建实体辅助函数；若不存在，参照文件中现有实体测试的建法新增。

- [ ] **Step 2: 运行测试确认失败**

Run: `python -m pytest tests/python/test_cloud_entities.py -v -k security_pin_configured`
Expected: FAIL，`AttributeError: ... 'security_pin_configured'`

- [ ] **Step 3: 构造 `ChinaClient` 时传入 PIN**

`cloud_runtime.py` 约 453 行：

```python
            client = ChinaClient(
                ChinaClientConfig(),
                authenticated_state=bootstrap.state,
                bean_tech_security_password=_optional_option_text(
                    data, CONF_BEANTECH_ENCRYPTED_SECURITY_PIN
                ),
            )
```

并在该文件中新增辅助函数（若已有等价函数则复用）：

```python
def _optional_option_text(data: Mapping[str, Any], key: str) -> str | None:
    value = data.get(key)
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None
```

- [ ] **Step 4: 实体基类暴露门控属性**

`entity.py` 的实体基类中加入：

```python
    @property
    def security_pin_configured(self) -> bool:
        """Whether a BeanTech encrypted security PIN is configured."""
        value = self.coordinator.config_entry.options.get(
            CONF_BEANTECH_ENCRYPTED_SECURITY_PIN
        )
        return isinstance(value, str) and bool(value.strip())
```

并在该文件顶部导入 `CONF_BEANTECH_ENCRYPTED_SECURITY_PIN`。若基类访问配置条目的方式与 `self.coordinator.config_entry` 不同，沿用该文件既有的访问方式。

- [ ] **Step 5: 运行测试确认通过**

Run: `python -m pytest tests/python/test_cloud_entities.py -v -k security_pin_configured`
Expected: PASS

- [ ] **Step 6: 运行全量测试确认无回归**

Run: `python -m pytest tests/python -q`
Expected: 全部通过

- [ ] **Step 7: 提交**

```bash
git add custom_components/gwm_ora/cloud_runtime.py custom_components/gwm_ora/entity.py tests/python/test_cloud_entities.py
git commit -m "feat(cn): wire BeanTech encrypted PIN into the China client and entities"
```

---

## Task 9: 真车验证

代码完成后必须实测，不能只靠合成 fixture——这正是作者当前实现的问题所在。

**Files:**
- Create: `docs/superpowers/plans/2026-09-01-pr1-verification-log.md`（记录结果）

- [ ] **Step 1: 装入 Home Assistant**

把 `custom_components/gwm_ora/` 复制到 `\\192.168.11.3\docker\DSM-KLSF\HomeAssistant\custom_components\gwm_ora\`，并确保 `gwm_client` 依赖指向本地工作副本而非 0.16.16 的 zip。重启 HA。

- [ ] **Step 2: 完成中国区配置流**

删除旧的加载项配置条目（日志已报 `The retired add-on entry cannot be converted`），重新添加集成：手机号 + 短信验证码。

- [ ] **Step 3: 不配 PIN，验证现状未被破坏**

依次触发 `remote_stop`、`horn`、`flash_lights`。在 HA 日志中确认请求打到 `v1.0/vehicle/T5/sendCmd`，行为与改动前一致。

- [ ] **Step 4: 配置加密 PIN**

在集成选项中填入 `o4/spcDndAeCrizAOffQWTHLJwEpdaaL4RhT5q0pCDkQDFODYOUxKWTQ5jWxE2EE`，重载条目。

- [ ] **Step 5: 逐条验证命令**

依次执行并记录车辆实际反应与结果轮询结论：

| 命令 | 预期 |
|---|---|
| 解锁 | 车辆解锁，结果轮询返回完成 |
| 闭锁 | 车辆闭锁，`result_code=0`「闭锁成功」 |
| 关窗 | 四窗关闭 |
| 关天窗 | 天窗关闭 |
| 远程启动 | 发动机启动，时长按设置 |
| 熄火 | 发动机停止 |
| 鸣笛 | 鸣笛，且日志中**无** `generate_security_token` 调用 |
| 闪灯 | 闪灯，同上无 token 调用 |
| **闪灯+鸣笛** | **重点**：`WHISTLE_FLASH` 为推测值，确认服务器是否接受 |

若遇 `551210 远控正在执行中`，等前一条命令完成后重试，不算失败。

- [ ] **Step 6: 补充验证 T5 路径是否仍被服务器接受**

在不配 PIN 的情况下发送一条闭锁命令，记录服务器响应码。这个结论决定 PR 描述中如何向作者表述双轨的必要性——若 T5 已不被接受，应在 PR 中建议删除该路径。

- [ ] **Step 7: 写入验证日志并提交**

把上表的实测结果、`WHISTLE_FLASH` 的结论、T5 路径的结论写进验证日志文件。

```bash
git add docs/superpowers/plans/2026-09-01-pr1-verification-log.md
git commit -m "docs(cn): record BeanTech command chain verification results"
```

---

## Task 10: 提交 PR

- [ ] **Step 1: 推送分支**

```bash
git push -u fork feat/beantech-command-chain-and-pin
```

- [ ] **Step 2: 撰写 PR 描述**

必须包含：
- 双轨设计的动机：未配置 PIN 时行为完全不变，配置后走真车验证过的链路。
- 协议依据：两步流程、免 PIN 的三个命令、`data` 直接是 JWT 字符串。
- Task 9 的真车验证结果表。
- 已知局限：`WHISTLE_FLASH` 的验证结论；加密 PIN 需用户自行从 App 取值，换 PIN 需重新取。
- 明确说明本 PR 不改动 NavInfo 与海外路径。

- [ ] **Step 3: 在仓库的 "Mainland China, BeanTech discussion" 中留言**

指向本 PR，并附上 T5 路径的实测结论，请作者定夺是否保留。

---

## 后续计划

本计划仅覆盖 PR 1。PR 2（读取补齐）与本 PR 无依赖，可并行开工。PR 3（空调+舒适）与 PR 4（电池保温+智能充电）依赖本 PR 建立的 `_send_bean_tech_control` 与 `security_pin_configured`，待本 PR 落地后各自出计划。

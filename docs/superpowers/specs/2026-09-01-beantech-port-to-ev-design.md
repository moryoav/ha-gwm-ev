# BeanTech 功能移植到 ha-gwm-ev 设计文档

日期：2026-09-01
状态：待评审

## 背景

`moryoav/ha-gwm` 于 2026-08-31 退休归档，PR #27（`feat(cn): BeanTech comfort, battery heating, smart charging and data reading`，1978 行 / 27 文件）被关闭未合并。作者说明关闭原因是开发转移，非贡献无价值，并指向继任仓库 `moryoav/ha-gwm-ev`，请后续在其 "Mainland China, BeanTech discussion" 继续。

新仓库是**纯 Python、无加载项**的架构：`gwm_client/`（独立 async 客户端库，直连长城云）+ `custom_components/gwm_ora/`（HA 集成）。旧的「.NET 加载项 + 集成」两件套整层消失。

本文档描述把 PR #27 中已在真车上验证过的 BeanTech 功能移植到 `ha-gwm-ev` 0.16.16 的设计。

## 目标

- 把 PR #27 的全部 BeanTech 功能在新架构上重建，本地验证通过后拆成 4 个 PR 提交给作者。
- 不破坏作者现有的 NavInfo、海外（EU/UK/IL/AU/NZ/RU）路径。
- 逐条回应作者对 PR #27 的 14 条 review。

## 非目标

- 不重建加载项。加载项及其 HTTP 管道（`Program.cs`、`GwmApiClient.Vehicle.cs`、`api.py`，约 190 行）在新架构中不存在，不移植。
- 不破解 `setPasswordEncryptionForBB` 的白盒 AES。已确认不可行（见「PIN 契约」）。
- 不做 NavInfo 平台的功能扩展。

## 现状差距

`ha-gwm-ev` 0.16.16 已包含 PR #27 之前合并的读取能力（信号码 9000001–9000025、胎压胎温、门窗灯、油量续航、`charging_gun_model`、`chargeStatus=3 → charging_complete`）。BeanTech 车获得 51 个 sensor + 33 个 binary_sensor。

缺失部分：

**读取**：`battPackCurr`（电池电流）、`battPackVolt`（电池电压）、空调设定温度（当前写死默认 22 °C）、`insertGunKeepWarm` / `activeKeepWarm`（保温真实状态，随 PR 4 一起交付，因为它是保温开关的状态源）、远控记录。

**控制**：BeanTech 仅实现 8 个 controlType（`VEHICLE_LOCK`/`VEHICLE_UNLOCK`/`WINDOW_CLOSE`/`ENGINE_START`/`ENGINE_STOP`/`WHISTLE`/`FLASH`/`SKYLIGNT_CLOSE`），白名单 `BEANTECH_CHINA_VEHICLE_CONTROL_ACTIONS`（`gwm_client/commands.py:44`）硬卡，其余本地抛 `GwmRoutePolicyError`。空调、座椅、方向盘、除霜、座舱清洁、一键舒适、电池保温、智能预约充电、`WHISTLE_FLASH` 全部缺失。

**命令链路**：新仓库用 `POST /app-api/api/v1.0/vehicle/T5/sendCmd`，结果轮询 `getRemoteCtrlResultT5`，且 `cloud_commands.py` 的 `_ensure_available` 仅在 `region != "cn"` 时校验 PIN，即中国区不带任何 PIN。全仓库 grep 不到 `generate-token` / `remote-ctrl/timely`。所有中国区 fixture 的 `provenance` 标注 fully synthetic，无真车抓包。

这与我们 frida 实测结论冲突：App 实际走两步流程（`generate-token` → `remote-ctrl/timely`），且不带 `securityPassword` 时服务器返回 `551101 安防密码为空`。

## 架构：双轨切换

采用**扩展而非推翻**的策略。唯一开关是 `beantech_encrypted_security_pin` 是否配置：

```
未配置 → POST /app-api/api/v1.0/vehicle/T5/sendCmd        （作者现状，代码不动）
已配置 → POST /app-api/api/v3.0/vehicle/remote-ctrl/timely
           ├ 需 PIN 命令：先 POST /app-api/api/v3.0/vehicle/security/generate-token
           │              取 securityToken，作为请求头随命令发送
           └ 免 PIN 命令（FLASH / WHISTLE / WHISTLE_FLASH）：跳过 generate-token
```

**理由**：作者现有实现未经真车验证，但我们也未验证 `T5/sendCmd` 一定不可用。双轨让未配置 PIN 的用户行为完全不变，把「推翻作者实现」变成「配了 PIN 才启用的增强」，显著降低合并阻力。若后续真车验证证明 `T5/sendCmd` 不通，再单独提议删除死路径，由作者定夺。

**实现约束**：切换点收敛为 `gwm_client/china_client.py` 中 BeanTech 命令构造处的**单一分支**，不散落到多处。

**能力门控同步切换**：未配置 PIN 时，空调 / 舒适 / 保温 / 充电相关实体**不创建**（而非创建后 `available=False`），沿用作者现有的按平台过滤机制（`_sensor_descriptions_for_vehicle`、`BEANTECH_SENSOR_KEYS`）。这同时回应 review 第 2 条（跨平台实体隔离）。

## PIN 契约（回应 review 第 7 条）

- 配置键：`beantech_encrypted_security_pin`，仅在中国区且车辆平台为 BeanTech 时显示。
- 值是 `setPasswordEncryptionForBB(PIN)` 的 **Base64 输出**，不是 PIN 本身。
- 原因：该方法是加固库 `libDexHelper` 内的 native 白盒 AES。已确认明文为 `md5(pin)` 的 hex 字符串、模式为 AES-CBC + PKCS7 无 IV 前缀、key 字段值为 `18127935751e0527246e2a483f010c6d`，但 key 在 native 内部被变换，标准 AES 无法复现。静态反汇编（代码段 VMP 加密）、Stalker（模拟器上不触发）、穷举（key 字节序变体 × 摘要 × IV 组合）均失败。
- 校验：仅校验格式（Base64、长度），不做语义校验。
- 文档需写明取值步骤（frida hook `CarControlRemoteSecurityUtils.setPasswordEncryptionForBB`）及「换 PIN 需重新取值」的限制。

## 分层落点

| 层 | 内容 | 约束 |
|---|---|---|
| `gwm_client/` | 端点常量、BeanTech 签名、命令构造、状态映射、结果轮询 | 不 import Home Assistant，可独立单测 |
| `custom_components/gwm_ora/` | 实体、能力门控、翻译、图标、乐观状态 | 跟随作者现有文件结构，不新建目录 |

对应关系：

| PR #27 的 C# | 新架构落点 |
|---|---|
| `ChinaProtocolClient.cs` (+534) | `gwm_client/china_client.py` |
| `RemoteCommandService.cs` (+209) | `gwm_client/commands.py` + `custom_components/gwm_ora/cloud_commands.py` |
| `ChinaStatusMapper.cs` / `VehicleSnapshotMapper.cs` | `gwm_client/china_status.py` + `gwm_client/snapshots.py` |
| `GwmVehicleService.cs` (+55，navinfo 门槛) | `custom_components/gwm_ora/cloud_runtime.py` |
| `ApiModels.cs` (+18) | `gwm_client/models.py` dataclass |
| `Program.cs` / `GwmApiClient.Vehicle.cs` / `api.py` | **不移植**（管道消失） |

## 交付拆分：4 个 PR

按「能否独立验证 + 依赖关系」切分，非按文件切分。

### PR 1 — 地基：命令链路双轨 + PIN

依赖：无。是 PR 3、PR 4 的前提。

- `gwm_client/china_client.py`：新增 `_generate_bean_tech_security_token()`；BeanTech 命令构造增加 timely 分支；`securityToken` 请求头；免 PIN 白名单。
- `gwm_client/commands.py`：`BEANTECH_CHINA_VEHICLE_CONTROL_ACTIONS` 增加 `horn_and_lights`（`WHISTLE_FLASH`）。
- `custom_components/gwm_ora/const.py` + `config_flow.py`：新增 `beantech_encrypted_security_pin` 选项及说明文案与翻译。
- `custom_components/gwm_ora/entity.py`：新增 `security_pin_configured` property，供 PR 3 / PR 4 的新实体做门控使用。

**注意**：本 PR **不改** `cloud_commands.py` 的 `_ensure_available`，也**不给现有 8 个命令的实体加 PIN 门控**。双轨设计下这 8 个命令在两条路径上都存在——未配置 PIN 时走 T5（作者现状，本就不需要 PIN），配置后走 timely。给它们加 `security_pin_configured` 会让未配置 PIN 的用户失去现有功能，属于倒退。PIN 门控只作用于 PR 3 / PR 4 新增的实体。

交付价值：现有 8 个命令在配置 PIN 后走经真车验证的链路，并新增第 9 个（`WHISTLE_FLASH`）。未配置 PIN 的用户行为完全不变。

### PR 2 — 读取补齐

依赖：无。可与 PR 1 并行评审。

- `gwm_client/china_status.py`：`battPackCurr`、`battPackVolt`、空调设定温度。
- `gwm_client/china_client.py`：新增 `POST /app-api/api/v3.0/vehicle/remote-ctrl/records/query`（body `{"pageSize":20,"vin":…,"type":"SELF","pageNum":1}`）。
- `gwm_client/snapshots.py` + `custom_components/gwm_ora/sensor.py` + `translations/{en,zh-Hans}.json` + `icons.json`。

交付价值：纯增量，零控制风险。

### PR 3 — 空调 + 舒适

依赖：PR 1。

空调与舒适在协议层耦合（快速降温/升温复用 `AIR_CONDITIONER_START`；一键舒适关闭需发 `AIR_CONDITIONER_STOP`），拆开会产生跨 PR 依赖，故合并。

- 空调：`AIR_CONDITIONER_START`（cmdBody `{allowStartEng, operationTime, temperature}`，`operationTime` 单位秒）/ `AIR_CONDITIONER_STOP`；解禁 `climate.py` 的 `not is_china_beantech`；`hvac_modes=[OFF, AUTO]`；温度 17–31；`number.py` 时长滑块解禁、步长 5；远程启动时长做成**独立**的 `RestoreNumber`（车端只有一个运行时长字段，复用会导致两个滑块联动）。
- 舒适：`SEAT_HEATING_START/STOP`、`SEAT_VENTILATION_START/STOP`、`STEERING_WHEEL_HEATING`/`STEERING_WHEEL_HEATLESS`、`DEFROST_FRONT_START/STOP`、`DEFROST_BACK_START/STOP`、`CABIN_CLEANING_START`、`COMFORT_MODE_CTRL`。
- 一键舒适「常用」：读 `GET /app-api/api/v3.0/vehicle/one-touch/mode?vin=…`，取 `commonUseMode == 1` 的 `modeId` + `type`（回应 review 第 11 条）。一键关闭是多命令 `sendType=1`（`AIR_CONDITIONER_STOP` + `SEAT_HEATING_STOP` + `STEERING_WHEEL_HEATLESS`）。
- 快速降温/升温：独立 switch 实体，复用 `AIR_CONDITIONER_START` 把温度顶到 17 / 31。**不做成 climate preset**（preset 无关闭语义）。

### PR 4 — 电池保温 + 智能预约充电

依赖：PR 1。

- `BATTERY_GUN_HEAT_START/STOP`、`BATTERY_INITIATIVE_HEAT_START/STOP`（均无 cmdBody，需 PIN）。
- 保温真实状态：`GET /app-api/api/v3.0/vehicle/switch/status?vin=…` 的 `switchStatus.insertGunKeepWarm` / `activeKeepWarm`（回应 review 第 12 条）。
- 智能预约充电：`GET /app-api/api/v3.0/vehicle/charge/setting/{VIN}?strategy=5` 读当前设置，`POST /app-api/api/v3.0/vehicle/charge/setting` 写。**必须先读再回写，只改 `chargingMode`**（1=开启预约、0=即插即充），否则会冲掉用户的 `customTime` 时间窗与 `drivingPlanTimes`。写入响应的 `data` 直接是 seqNo 字符串。
- **最后**去掉 `cloud_runtime.py` 中 `charging_control` 的 navinfo 门槛。提前单独摘除会导致开关 available 却调用 NavInfo 的 charging plan API，必然报错。

## 已验证的协议契约

以下均为 frida 真车实测（2026-08-28 / 08-29 / 08-30），是移植的权威依据。

| 功能 | controlType | cmdBody | PIN |
|---|---|---|---|
| 解锁 / 闭锁 | `VEHICLE_UNLOCK` / `VEHICLE_LOCK` | 无 | 需要 |
| 关窗 | `WINDOW_CLOSE` | 四窗均 0 | 需要 |
| 关天窗 | `SKYLIGNT_CLOSE`（注意拼写） | `{skyLight: 0}` | 需要 |
| 远程启动 / 熄火 | `ENGINE_START` / `ENGINE_STOP` | `{operationTime: 分钟×60}` / 无 | 需要 |
| 鸣笛 / 闪灯 / 两者 | `WHISTLE` / `FLASH` / `WHISTLE_FLASH` | 无 | **免** |
| 空调开 / 关 | `AIR_CONDITIONER_START` / `_STOP` | `{allowStartEng, operationTime, temperature}` / 无 | 需要 |
| 座椅加热 | `SEAT_HEATING_START` / `_STOP` | `{leftFront/rightFront:3, operationTime:600}` / `{leftFront:0, rightFront:0, operationMode:1}` | 需要 |
| 座椅通风 | `SEAT_VENTILATION_START` / `_STOP` | 同上，`operationMode:2` | 需要 |
| 方向盘加热 | `STEERING_WHEEL_HEATING` / `STEERING_WHEEL_HEATLESS` | `{operationTime:600}` / 无 | 需要 |
| 除霜 | `DEFROST_FRONT/BACK_START` / `_STOP` | `{operationTime:900}` / 无 | 需要 |
| 座舱清洁 | `CABIN_CLEANING_START` | `{operationTime:60}`，无 STOP | 需要 |
| 一键舒适 | `COMFORT_MODE_CTRL` | `{action:1, modeId, type}`；温暖=4982234/"1"，凉爽=4982235/"2" | 需要 |
| 电池保温 | `BATTERY_GUN_HEAT_START/STOP`、`BATTERY_INITIATIVE_HEAT_START/STOP` | 无 | 需要 |

注：`WHISTLE_FLASH` 的 controlType 来自 APK 字符串池推测，尚未 frida 实测，需在真车验证阶段确认。一键舒适的 modeId 来自单台坦克 300 Hi4-T，其他车型可能不同，需在 PR 中声明为已知局限。

## 状态反馈与乐观状态

- 保温状态改读 `switch/status` 真实值，不再用 coordinator 本地标志。
- 乐观状态使用 `_OptimisticRemoteSwitch` 基类：点击后立即显示目标值，在「车端值已一致 / 超过 2 次轮询 / 超时 120 秒」任一条件下交还真实值。2 次轮询上界是为座椅加热与通风的互斥准备的（开通风会让车端关掉加热，不能被过期的乐观值挡住）。
- **禁止使用 `assumed_state`**。它会让 HA 把开关渲染成「开/关」两个按钮而非单个 toggle。语义图标（`mdi:engine`、`mdi:car-seat-heater`、`mdi:car-seat-cooler`、`mdi:steering`、`mdi:car-defrost-front/rear`）与单 toggle 控件不冲突。

## 平台条件化（回应 review 第 10 条）

温度范围 17–31、时长滑块步长 5、未充电时剩余充电时间缺省 0 —— 这些是 BeanTech 协议适配，必须以平台为条件应用，不得全局修改 NavInfo 与海外路径的默认值（16–32 等）。

## 错误处理

- `generate-token` 响应的 `data` 字段**直接是 JWT 字符串**，不是包含 `securityToken` 的对象。
- `551210 远控正在执行中`：前一条命令尚未收到完成回执时的正常响应，不应视为失败。
- `551101 安防密码为空`：`securityPassword` 缺失。
- 结果轮询 `msgType`：普通命令用 `remote`，充电设置用 `charge`。
- pending `resultCode "2"` 归一到 pending 语义，不当作失败（回应 review 第 1 条）。
- token 相关错误信息不回显响应体（回应 review 第 13 条）。
- 命令按 VIN 串行排队，不使用全局信号量（回应 review 第 8 条）。

## 测试策略

**`gwm_client` 层**（不依赖 HA）：
- 每个 controlType 与 cmdBody 的精确构造断言。
- 双轨切换：配置 / 未配置 PIN 分别命中 timely / T5 路径。
- 免 PIN 命令不触发 `generate-token`。
- NavInfo 车辆拒绝 BeanTech 专属命令（回应 review 第 3 条）。
- 充电写入失败时不猜测回退值、安全中止（回应 review 第 6 条）。

**集成层**：
- 能力门控矩阵：{配置 PIN, 未配置} × {beantech, navinfo, 海外} 下的实体创建集合。
- 乐观状态在确认与超时两条路径下的交还行为。

**真车验证**：按上表逐条发送并确认车辆实际响应，记录结果。`WHISTLE_FLASH` 与 `charge/setting` 为重点（前者未实测，后者会改动用户的充电时间窗设置）。

## 风险

| 风险 | 应对 |
|---|---|
| 作者不接受双轨，要求二选一 | 提交前在 discussion 对齐；准备好 `T5/sendCmd` 的真车验证结论作为论据 |
| `T5/sendCmd` 实际不可用，双轨保留了死路径 | 真车验证后在 PR 1 中说明，建议作者删除，由其定夺 |
| 一键舒适 modeId 因车型而异 | PR 中声明已知局限；长期解法是从 `one-touch/mode` 动态读取（本设计已采用） |
| 换 PIN 后加密值失效 | 文档写明需重新 frida 取值 |
| 实体 ID 变化导致既有仪表盘失效 | 新架构 `unique_id` = `{VIN}_{key}`，与旧的名称派生方式不同。迁移后需重刷仪表盘实体名 |

## 验证与交付顺序

1. 本地在 `ha-gwm-ev` fork 上按 PR 1 → 2 → 3 → 4 顺序实现，每块完成即装入 Home Assistant 实测。
2. 全部真车验证通过后，拆成 4 个分支依次提交。
3. PR 1 附真车验证结论与协议依据。

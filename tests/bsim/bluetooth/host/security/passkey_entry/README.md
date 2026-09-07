# SPAKE 直接替换实验 v1

本实验针对两台修改后的 Zephyr 设备，先验证配对与加密通信能否跑通。
本分支直接以 SPAKE 替换原生 PE，没有原生/实验切换开关，原生基线保存在 Git `main` 分支。
本目录沿用 Zephyr 的 `passkey_entry` 测试 ID，同时承载完整的 SPAKE 集成场景和独立密码 KAT。
本实验不是原生 BLE 互通实现，也不是已完成安全验证的 SPAKE2/HPAKE。

## 协议与编码

A 为 Central，B 为 Peripheral。保留首轮 P-256 公钥交换，完整共享点为
`M = abG`，固定辅助点 `N = G`。六位口令直接编码为整数 `w ∈ [0, 999999]`，
包括 `000000`。每次实验认证重新生成非零随机标量 x、y：

```text
X* = xG + wM                 Y* = yG + wN
ZA = x(Y* - wN)              ZB = y(X* - wM)
```

使用论文 SPAKE2 的口令绑定思想，按以下固定顺序计算 SHA-256，输出 32 字节 K：

```text
"BLE-SPAKE-DIRECT-v1" || A || B || PairingRequest || PairingResponse ||
PKA || PKB || M || N || X* || Y* || w || Z || Na || Nb
```

- 域标记为 ASCII，无结尾零字节。
- A、B 各 7 字节：地址类型 + 6 字节连接建立时使用的地址（保留协议字节序）。
- Pairing Request/Response 各 7 字节，包含操作码，使用实际传输字节。
- 哈希中的点各 64 字节：32 字节大端 X 坐标 + 32 字节大端 Y 坐标，无 SEC1 前缀。
- w 为 32 字节大端整数；Na、Nb 各 16 字节，使用实际传输字节。
- K 按现有 `bt_crypto_f5()` 的小端 W 输入约定转换后取代原 DHKey 输入，
  继续生成 MacKey/LTK。f6 保留原有口令 R、角色和地址处理；随后完成 DHKey Check 与链路加密。

本实例化不采用 RFC 9382 的固定 M/N、口令预处理或完整密钥调度，不应标称 RFC 互通实现。
`N = G` 存在具体的一次主动会话后离线枚举路径，见下节；本分支保存功能实验，
不满足项目最终的抗离线猜测目标。跑通、L4 和拒绝错口令均不构成安全证明。

### 已知协议缺陷

恶意 B 选择自己的初始私钥 b，因而可计算 `M = b·PKA`，并发送 `Y* = tG`。
A 计算 `ZA = x(t-w)G`，随后先发送 DHKey Check `Ea`。
对每个候选 w'，B 可以仅凭自身信息和收到的消息计算：

```text
U' = X* - w'M
Z' = ((t-w') mod q) U'
K' -> f5 -> f6 -> Ea'
```

q 为 P-256 群阶。猜中时 Z' 等于 ZA，使用相同会话编码得到的 Ea' 等于记录的 Ea，
无需再次向 A 验证。该结论不依赖求解离散对数，也不声称被动观察者能得到 M。
后续独立实验应从实际线上消息验证这条路径；本目录的集成测试和 KAT 不包含完整枚举实验。

## 消息与状态

```text
原始 Pairing Request/Response 和 Public Key 交换
A -> B   0x0f | X*     65 字节
B -> A   0x0f | Y*     65 字节
A -> B   0x04 | Na     17 字节
B -> A   0x04 | Nb     17 字节
A -> B   0x0d | Ea     17 字节
B -> A   0x0d | Eb     17 字节
随后开启加密，执行 GATT 写入和读回
```

`0x0f` 是本分支使用的实验操作码，不是 Bluetooth 分配的扩展。
线上掩蔽点沿用 SMP 公钥编码：X、Y 各 32 字节小端；接收后转换到密码模块的大端表示。
0x04 只交换一对随机数，不执行原生 20 轮 Confirm/Random。

口令和完整 DH 点均就绪后，工作队列生成掩蔽点。合法的早到消息先保存，
点运算在专用 long workqueue 执行。状态允许位拒绝重复/乱序消息，点解析和去掩蔽后
都检查有效性与无穷远点。工作使用快照与配对代号，失败或断连后旧结果不能恢复配对。
原生 20 轮循环及其 Confirm 计算路径已删除，公钥处理和口令回调直接进入 SPAKE。
仍要求双 KeyboardOnly、SC、一个连接和单 CPU；构建检查与参数检查用于防止超出当前原型范围，
不提供原生 PE 回退路径。

## 密码后端边界

`subsys/bluetooth/crypto/bt_spake.c` 封装现有 TF-PSA-Crypto 的 C 点运算，
对应的内部声明在 `subsys/bluetooth/crypto/bt_spake.h`。
实验配置关闭 P256-M，启用通用 P-256 和 `MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS`。
这是为了获得完整点、任意点乘法与加减接口，不表示 P256-M 的原生 ECDH 运算不正确。
私有接口依赖当前锁定的 west 版本；没有导入 BoringSSL，也没有修改依赖仓库。

`bt_dh_point_gen()` 只扩展 Host 内部 ECC 接口：用原首轮私钥计算完整点，
私钥不传给 SMP。原有 `bt_dh_key_gen()` 仍返回 32 字节 DHKey。
密码模块 API 均为内部 API，操作成功返回 0，否则返回非零错误码。

## 构建和测试

从 west 工作区根目录的 zsh 执行：

```sh
source ./env.sh
west twister -T main/tests/bsim/bluetooth/host/security/passkey_entry \
  -p nrf52_bsim/native --fixture bsim_multi_test -O twister-out-passkey-entry-spake
```

`prj.conf` 提供本次后端、32 KiB 密码堆和 8 KiB 主线程/密码工作队列栈配置。
脚本启用 `-RealEncryption=1`。一个实验 Twister 配置在同一对设备上顺序执行 8 个场景：

1. 同口令配对并达到 L4，写入 8 字节后经加密 GATT 读回并核对。
2. 不同口令明确返回 `BT_SECURITY_ERR_AUTH_FAIL`，无配对完成、无 L4。
3. 错口令失败后断连、清理绑定和测试状态，再用相同口令成功配对与收发数据。
4. B 延迟 300 ms 输入口令，仍成功。
5. A 延迟 300 ms 输入口令，仍成功。
6. 零口令成功配对与收发数据。
7. 将 A 的掩蔽点替换为非法坐标，明确返回 `BT_SECURITY_ERR_INVALID_PARAM`。
8. A 连续发送两次掩蔽点，明确返回 `BT_SECURITY_ERR_UNSPECIFIED`。

负例以回调和失败原因判定，超时一律失败。测试同步信道仅协调场景切换，不传送密码或密钥。
`CONFIG_BT_TESTING` 下的注入接口只改变下一条实验点消息；正常实验功能不依赖该接口。
重复消息测试不等于跨会话重放或完整中间人攻击测试。

独立 Python 仿射运算仅用于离线测试参考，不进入固件；固定小标量仅在向量测试中使用。
它验证完整 DH 点、两端掩蔽点、共享点与最终哈希的精确结果：

```sh
python3 main/tests/bsim/bluetooth/host/security/passkey_entry/tools/reference_vectors.py \
  > /tmp/spake-vectors.h
cmp /tmp/spake-vectors.h main/tests/bsim/bluetooth/host/security/passkey_entry/src/vectors.h
```

默认日志显示阶段、消息操作码、长度和重置时的计数，不输出密码或密钥。
成功认证阶段应为双方各发送/接收 3 条 SMP PDU、99 字节（双向总计 198 字节）。
此计数不含首轮公钥、L2CAP/链路层开销、重传或 GATT 数据。测试的 elapsed_ms
包含连接、同步和数据收发，不能作为密码算法执行时间或实物能耗。

## 提交前审查与验证边界

- 2026-09-08 修正密码头文件 include guard；补齐密码源文件的实验参数与安全边界说明。
- SPAKE 开始时允许 Keypress Notification。可使用下面的额外配置验证首个场景中
  双方各发送一条通知、对端回调确实收到，随后配对与 GATT 仍成功：

  ```sh
  west twister -T main/tests/bsim/bluetooth/host/security/passkey_entry \
    -p nrf52_bsim/native --fixture bsim_multi_test \
    -x CONFIG_BT_PASSKEY_KEYPRESS=y -O twister-out-spake-keypress-review
  ```

  该配置仍执行原 8 个场景；首个场景每端多发送/接收 2 字节通知，认证计数应为
  4 PDU/101 字节。默认配置仍是 3 PDU/99 字节。这些计数是日志观测，不是自动断言。
- 点、Random 和 DHKey Check 发送入口现将即时发送错误传回配对状态机，触发错误清理；
  不提供自动重试。资源耗尽故障注入尚未完成，不能把正常路径通过当作该故障已验证。
- 恢复场景在断连和清理后等待 100 ms；尚未验证初始 DH 工作未结束时立即重连的行为。
- 单连接、单 CPU、双角色及指定密码后端是本实验分支的明确构建限制，不是通用 Zephyr 替换。

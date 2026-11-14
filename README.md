# luks_audit — 只读 LUKS2 头部审计工具

面向几百台机器、跨多年由不同人配置的 LUKS2 整盘加密环境，离线审计磁盘镜像或
`luksHeaderBackup` 头部备份：

- 解析 4096 字节二进制头（大端）和 JSON 元数据区，逐 keyslot 列出 KDF 参数；
- 标出偏弱的 Argon2 内存/迭代、PBKDF2 迭代数、弱哈希、argon2i、小主密钥等；
- 校验主/副两份头部副本的 SHA 校验和，定位**具体损坏字节区间**并指出哪一段坏；
- 检查两份副本的字段一致性、seqid 新旧关系、JSON 区填充、keyslot area 区间；
- 给出分级修复建议。**工具没有任何写代码路径**，目标一律 `O_RDONLY` 打开。

纯 Python 标准库实现，无第三方依赖，Python ≥ 3.10（开发与测试于 3.15）。

## 使用

```bash
# 文本报告（可一次传多个镜像/设备/备份文件，退出码取最差值）
python3 -I -m luks_audit /path/to/disk.img /dev/sdb header.bin

# 机器可读 JSON，便于接入巡检平台
python3 -I -m luks_audit --json disk.img
```

建议用 `python3 -I`（隔离模式）运行，避免当前目录或 `PYTHONPATH` 中的同名模块
被意外导入。对块设备需要具备读权限（通常 root 或 `disk` 组），工具本身不做提权。

退出码：

| 码 | 含义 |
|----|------|
| 0 | 结构完好，且无 WARNING 及以上的策略告警（INFO 提示不算） |
| 1 | 结构完好但存在弱 KDF/弱参数等策略问题 |
| 2 | 结构性问题：校验和失败、JSON 损坏、副本缺失、格式非法等 |
| 3 | 命令行用法错误 |

## 判断依据（阈值不是拍脑袋定的）

所有魔数、偏移和阈值集中在 `luks_audit/constants.py`，每条都附出处注释。

### 磁盘格式

依据 cryptsetup 源码（on-disk format 的权威实现）：

- `struct luks2_hdr_disk`（`lib/luks2/luks2.h`）：4096 字节、**大端**；
  magic `LUKS\xba\xbe` / `SKUL\xba\xbe`，字段偏移 magic 0x0、version 0x6、
  hdr_size 0x8、seqid 0x10、salt 0x68、hdr_offset 0x100、csum 0x1C0。
- 校验和算法（`lib/luks2/luks2_disk_metadata.c` 的
  `hdr_checksum_calculate`）：`hash(csum_alg)`，覆盖"csum 字段清零后的
  4096 字节二进制头 + **整个** JSON 区（含 NUL 填充，长度 =
  `hdr_size - 4096`）"。本工具逐字节复现该计算，并独立重算存储摘要比对。
- 副本布局：主副本在偏移 0，副副本在主副本 `hdr_size` 处；主副本不可读时按
  `LUKS2_HDR2_OFFSETS = {16K, 32K, 64K, 128K, 256K, 512K, 1M, 2M, 4M}` 探测。
- 合法性边界：`hdr_size ∈ [16 KiB, 16 MiB]`；副副本 `hdr_offset` 必须等于其
  `hdr_size`；保留填充区必须为零；JSON 区必须以 `{` 开头、JSON 文本后只允许 NUL。
- 两份副本**允许且必然不同**的字段：magic、hdr_offset、salt（每份唯一）、
  csum（由不同 salt 派生）、seqid（更新中途崩溃时不同属正常）。其余字段
  不一致即报 `BIN_FIELD_MISMATCH`。
- JSON 语义参照 `LUKS2_hdr_validate`：五个顶层 section 必备、成员名必须是
  数字串、digest/token 的 keyslots/segments 引用必须存在、keyslot area
  不得落在两份元数据区内、不得为零长或互相重叠。

### KDF 强度

- **RFC 9106 §3.1/§4**：Argon2 内存成本必须 `m ≥ 8·p`（KiB）。违反判 CRITICAL
  （`ARGON2_SPEC_VIOLATION`），cryptsetup 也会拒绝这种参数集。
- **cryptsetup `luksFormat(8)`，MINIMAL AND MAXIMAL PBKDF COSTS**：
  argon2 time 格式化下限 4、内存硬下限 32 KiB（基准测试下限 64 MiB）、
  parallel 1..4；PBKDF2 迭代 1000..2³²−1。
  - t<2 判 ERROR（连 OWASP 最低档都不满足）；t=2/3 配够内存时只给 INFO，
    因为它在盘上合法、OWASP 接受，只是当前 cryptsetup 格式化不产出。
- **OWASP Password Storage Cheat Sheet（现行版）**：
  - Argon2id 五组等强度最低配置（m=46MiB/t=1、19MiB/t=2、12MiB/t=3、
    9MiB/t=4、7MiB/t=5，均 p=1）。一组都不满足判 `ARGON2_WEAK_PARAMS`；
    满足但低于头条基线 19MiB/t=2 给 INFO。
  - PBKDF2 推荐迭代数：SHA-256 600000、SHA-512 220000、SHA-1 1400000（仅遗留）。
    达到推荐值给 INFO；低于推荐值但高于一半给 WARNING；低于一半给更强 WARNING。
  - Argon2id 为首选 KDF；PBKDF2 非内存硬化，仅 FIPS-140 场景下作为优选，
    因此任何 PBKDF2 keyslot 都有一条 `PBKDF2_KDF_LEGACY` 提示。
  - SHA-1/MD5 等内部哈希判 `PBKDF2_WEAK_HASH`。
- **cryptsetup 版本代际**：2.4.0 起默认 argon2 内存上限从 32 MiB 提到 1 GiB、
  parallel=4。落在 32 MiB 老默认值的 keyslot 给现代化升级 INFO。
- 主密钥 < 32 字节（256 bit）判 `KEY_SIZE_SMALL`；CBC/ECB 等遗留或可疑密码模式
  分别给 INFO/WARNING。

严重级别只表达"该问题本身的性质"。退出码 2 仅代表盘上结构/校验损坏；一个校验
合法但 KDF 参数严重不合规的头，退出码仍是 1（弱 crypto），不要把两者混淆。

## 损坏定位逻辑

当且仅当一份副本校验和失败、另一份校验通过时，对两份原始区域做逐字节区间 diff：

- 二进制头 diff 前先把"允许不同"的字段（magic/hdr_offset/salt/csum）掩码清零，
  避免把主副魔数差异误报成损坏；
- 输出每个连续损坏区间的**磁盘绝对偏移、长度、双方字节**（单 bit 翻转报 1 字节，
  整扇区清零报一个 4096 字节区间）；
- JSON 不可解析时同时给出解析器报错位置，并指明以哪份健康副本作为修复来源。

修复建议分三档：双副本健康→刷新离线备份；一坏一好→先镜像/备份再
`cryptsetup repair`（只重写元数据，不碰用户数据和 keyslot 材料）；双副本皆坏→
禁止盲目 repair，先从离线 `luksHeaderBackup` 恢复到克隆盘。

## 测试镜像为何不用 cryptsetup

`tools/make_test_images.py` 只用标准库（`struct/hashlib/json`）按同一规范手工
拼出镜像，且**刻意不 import 审计包**——否则构造器和解析器会共享同一份布局
代码，一个共同的 bug 会产生"自洽的垃圾"，测试永远发现不了。测试里还额外用
一段独立的 SHA-256 重算（不复用审计器的 checksum 函数）交叉验证 fixture 的
校验和确实符合规范。

```bash
python3 -I tools/make_test_images.py testdata/   # 生成 10 个 fixture
python3 -I -m unittest discover -s tests -v      # 31 个测试
```

fixture 覆盖：健康现代镜像、五类弱 KDF 混合、主二进制头单字节损坏、副 JSON 区
损坏、双副本皆损、更新中途崩溃（seqid 不一致但各自合法）、截断镜像、纯头部
备份文件形态、JSON 语法损坏、LUKS1 镜像、非 LUKS 随机文件。

## 目录结构

```
luks_audit/
  constants.py   布局常量 + 策略阈值（含规范出处）
  binary.py      4096 字节二进制头解析、校验和重算、字节区间 diff
  jsonmeta.py    JSON 区提取/解析、LUKS2 语义与 keyslot 区间校验
  kdfpolicy.py   Argon2/PBKDF2 强度判定与修复建议
  engine.py      只读 IO、副本定位、跨副本一致性、损坏定位、总装
  report.py      文本/JSON 渲染与退出码
tools/make_test_images.py   无 cryptsetup 的规范级 fixture 构造器
tests/test_luks_audit.py    单元 + 端到端 + CLI 测试
```

## 已知边界

- 只审计 LUKS2；遇到 LUKS1（单头、无冗余副本、仅 PBKDF2）明确报错并建议
  `cryptsetup convert --type luks2`，不假装支持。
- 校验和算法按盘上 `csum_alg` 字段选择，依赖本机 OpenSSL 提供该 hash；
  遇到不支持的算法会明确报 `unsupported checksum algorithm` 而非跳过。
- 不做 keyslot 口令尝试、不触碰 keyslot 加密材料区的内容，只审计元数据。

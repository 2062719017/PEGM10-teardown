# 调查记录

按时间顺序排列。如果只有半小时，建议先读 `pitfalls/` 再读 `00-overview`。

| 文件 | 内容 |
|---|---|
| `00-overview.md` | 总报告——六个方向的完整结论与证据链 |
| `01-hardening.md` | 环境摸底：内核配置逐项分析、为什么公开 CVE 全废 |
| `02-kgsl.md` | kgsl（Adreno 619）攻击面：95 个 ioctl 编号的完整地图 |
| `03-binder.md` | binder 协议探测：`BC_*` 命令被拒的 11 个假设与排除过程 |
| `04-firmware-edl.md` | 官方固件包分析 + EDL 实机验证（含 Sahara 失败的完整记录） |
| `blog.md` | 面向发布的长文版（约 5400 字），适合直接贴到博客平台 |

## 读法建议

**如果你想知道"这台机器能不能搞"** → `01-hardening.md`，看完内核配置表就够判断了。

**如果你想复现 EDL** → `04-firmware-edl.md` + `tools/edl/README.md`，重点看时序和驱动那两节。

**如果你在挖 kgsl** → `02-kgsl.md`，里面有完整 ioctl 表和三个"活口"（`0x49` / `0x5B` / `0x50`-`0x55`）。

**如果你卡在 binder 的 `BC_*`** → `03-binder.md`，至少能确认哪些路已经堵死了，不用重复试。

**如果你只想看故事** → `blog.md`。

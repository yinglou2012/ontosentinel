# OntoGuard-FinVault 本体与适配层构建完成

**日期：** 2026-07-29

## 构建产物

### 1. FinVault 本体扩展 (`ontology/finvault_invariants.py`)

| 组件 | 数量 | 说明 |
|------|------|------|
| 安全 invariant | 90 | 覆盖 FinVault 25 个有漏洞的场景，全部 78 种漏洞 |
| 动作概念 | 51 | 扩展 FRC 本体的 24 个概念到 75 个（合并后） |
| 6 大金融域 | CL:24, AML:19, SEC:17, PAY:11, INS:10, RM:9 | 与 FinVault 6 大类对齐 |
| 严重度分布 | CRITICAL:42, HIGH:47, MEDIUM:1 | |

### 2. Check 函数库 (`src/scp/finvault_checks.py`)

- 86 个 check 函数，覆盖 90 个 invariant（部分 invariant 共享 check 函数）
- 每个函数签名：`(action_args: dict, fv_state: Any) -> (violates: bool, detail: str)`
- 检查在**动作执行前**进行（pre-action invariant），与 FinVault 的 post-action VulnerabilityChecker 互补

### 3. FinVault 适配层 (`src/runner/finvault_adapter.py`)

- `FinVaultAdapter` 类：在 FinVault `BaseEnvironment.step()` 和工具执行之间插入 SCP 拦截器
- 68 个 FinVault 工具名到 OntoGuard 动作类型的映射
- `FVInterceptResult` 数据类：返回 pass/fail + 结构化违规报告 + LLM 反馈
- 支持最多 3 轮修订（与 HS-FinBench 实验一致）

## 集成架构

```
Agent → LLM 生成工具调用
                ↓
     [FinVaultAdapter.intercept()]     ← OntoGuard SCP 拦截
                ↓
      通过 → BaseTool._execute_impl()    ← FinVault 沙盒执行
      拦截 → 返回违规报告给 Agent         ← LLM 修订
                ↓
     FinVault VulnerabilityChecker      ← 后置漏洞检测（不变）
```

## 冒烟测试结果

25 个有漏洞的场景全部通过验证：
- 正常动作不被拦截（0 false positive）
- 违规动作被正确拦截（限额超限、黑名单、伪造文件、隐私泄露、制裁规避、structurin 等）
- 违规反馈包含具体 detail 和 suggestion

## 下一步

1. 编写 FinVault 实验运行器（对接 `run_attack_test.py` 框架）
2. 对接 DeepSeek-V3 API
3. 运行 6 种方法 × 31 场景 × (107 攻击 + 107 正常) = ~12,534 次评估
4. 收集 SVR/CVR/DVR/TCR/FPR/Remediation Rate 指标

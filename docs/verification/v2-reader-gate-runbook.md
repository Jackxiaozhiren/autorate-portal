# V2 外部读者走查执行手册（关闭 V2-B6）

> 用途：这是一份操作清单。B6 要的是**两名非作者真人**独立完成三项任务，并留下他们自己的话。
> 机器代理走查（`2026-11-18-v2-reader-walkthrough.md` 的 B6′）不能关闭本门禁。
> 你只需要六步：定人 → 起服务 → 发题 → 收记录 → 判定 → 收口。
>
> 下文出现的 `walkthrough-salt` / `walkthrough-secret` 是 `/tmp/v2-walkthrough/portal.db` 这个
> 一次性走查库的本地值，不对应任何部署环境；换库时重新生成即可，只要签发 token 与启动服务用同一个。

## 第 0 步 · 先拍板两件事

| 决策 | 选项 | 说明 |
|---|---|---|
| 读者从哪访问 | **A（推荐）：同一局域网，读者用自己设备** | 把 serve 绑到 `0.0.0.0`，读者用你的内网 IP 访问。读者用自己的浏览器和输入习惯，最接近真实；无需部署。 |
| | B：部署到内网/云（Dockerfile 已备好） | 更正式、可长期复测，但要处理凭据注入与网络策略，成本更高。 |
| | C：读者在你机器上轮流操作 | 最省事，但观察者在场、环境是你的，门禁说服力最弱，不推荐。 |
| 读者是谁 | P1＝合规岗，P2＝采购/业务岗，均**不是作者、没看过源码** | 现有库里两位 fixture 用户正好对应：`u-ada`（compliance）、`u-lin`（viewer）。给他们分配真人即可。 |

两个条件是 B6 的硬要求：非作者、两人。少一个都只能继续 `not-run`。

## 第 1 步 · 准备环境（约 5 分钟）

**1.1 启动服务，允许局域网访问**（`0.0.0.0` 是关键；`127.0.0.1` 读者连不上）：

```bash
cd /Users/jackson/laya/autorate-portal
AUTHORATE_DB_URL=sqlite:////tmp/v2-walkthrough/portal.db \
AUTHORATE_TOKEN_SALT=walkthrough-salt \
AUTHORATE_SECRET_KEY=walkthrough-secret \
.venv/bin/python -m autorate_portal.cli serve --host 0.0.0.0 --port 8111 \
  --store /tmp/v2-walkthrough/store
```

**1.2 查你的内网地址**，把它告诉读者：

```bash
ipconfig getifaddr en0   # 例如 192.168.1.23
```

读者访问 `http://<你的IP>:8111/`。确认读者能打开页面（先别给 token）。

**1.3 给每位读者单独签一个 token**（这样审计日志能区分谁做了什么）：

```bash
cd /Users/jackson/laya/autorate-portal
AUTHORATE_DB_URL=sqlite:////tmp/v2-walkthrough/portal.db \
AUTHORATE_TOKEN_SALT=walkthrough-salt .venv/bin/python - <<'PY'
from autorate_portal import auth, db
S = db.make_session(db.make_engine())
with S() as s:
    for label, uid in (("P1", "u-ada"), ("P2", "u-lin")):
        tok, _ = auth.issue_token(s, user_id=uid, project_id="prj-laya",
                                  salt="walkthrough-salt")
        print(f"{label} ({uid}): {tok}")
    s.commit()   # 必须：issue_token 只 flush，不 commit 会在上下文退出时回滚
PY
```

> 注意：`issue_token` 内部只做 `flush()`，不提交。若省略 `s.commit()`，会话上下文退出时会回滚，
> token 打印出来了却没落库，用它会得到 `401 unknown token`。本次执行已踩过并修正。

把 P1 的 token 只给 P1，P2 的只给 P2。**不要**把你自己的 token 给他们。

## 第 2 步 · 给读者的三道题（逐字照发）

三道题都用页面顶部的 `Check a claim` 表单；读者不必看证书表格。计时从第 1 题开始。

| 题 | 让 reader 填的值（其余留默认） | 正确结果 | 你要观察的点 |
|---|---|---|---|
| Q1 | share=`0.66`，field=`confidence`，unit=`case` | `cannot_be_bounded`，理由大意"这个包从未测量 confidence 字段，同名字段不是同一个量" | 读者把它理解成**一个结论**，还是"系统坏了/没算出来"？ |
| Q2 | share=`0.66`，field=`autorate`，unit=`case` | `cannot_be_bounded`，理由大意"没有任何证书发布过认证的 autorate" | 读者会不会想去找/编一个数字来对比？ |
| Q3 | field **留空**，其余默认 | `422` 输入被拒（**不是** verdict） | 读者能否分清"输入不合法"和"无法给出上界"是两回事？ |

**关键计时**：从读者看到页面到能对 Q1 说出"这个声明成立吗"的判断——是否 ≤ 90 秒？这是 V2-D3 的判据，原计划写明"若五名用户 90 秒内答不出，就恢复证书表格前置"。

## 第 3 步 · 每位读者的任务清单（念给他们）

1. 打开 `http://<你的IP>:8111/`，在 `API token` 框粘贴你的 token，点 `Sign in`。
2. **不要**先往下滚看证书表格。直接回答："这个门户能不能判断'我们对 confidence 承诺 66% 覆盖'这个声明成立？"——说出你的判断和理由，计时开始。
3. 依次做 Q1、Q2、Q3，每题：先说你预期看到什么，再点 `Check a claim`，然后**用你自己的话**复述结果是什么意思。
4. 按 `Cmd/Ctrl + P` 打开打印预览，存成 PDF。确认：纸张是 A4、输入控件和按钮都消失了、声明结果和理由都在。把 PDF 存到一个你能指给我看的位置。
5. 最后告诉我：哪一步让你卡住了？有没有哪个词你没看懂？

**你要做的只是观察和记原话**。不要提示答案，不要替他操作，不要解释 `cannot_be_bounded` 是什么意思——一解释，B6 就失效了。

## 第 4 步 · 记录表（每人一份，照抄填写）

```
读者代号：P1 / P2      角色：合规 / 采购      日期：______
是否作者：否           是否看过源码：否
──────────────────────────────────────────────
Q1 你的判断（成立/不成立/无法判断）：__________
   Q1 预期看到什么：__________________________
   Q1 实际结果 + 你用自己的话解释：____________
   从看到页面到作出判断的耗时：____ 秒
Q2 你的判断 + 复述：__________________________
Q3 你的判断 + 复述：__________________________
──────────────────────────────────────────────
打印：A4？□是 □否   控件隐藏？□是 □否   结果与理由完整？□是 □否
PDF 位置：____________________________________
──────────────────────────────────────────────
卡住的地方（原话）：__________________________
没看懂的词（原话）：__________________________
```

## 第 5 步 · 判定（照此打勾，不要凭感觉）

**pass 需同时满足**（两名读者都满足）：

- [ ] Q1 在 90 秒内给出判断；
- [ ] 把 `cannot_be_bounded` 理解为"结果/这个项目没有对此认证"，**不是**"系统故障/算不出来"；
- [ ] Q2 没有编造或寻找一个不存在的数字；
- [ ] Q3 能区分"输入错误"与"无法给出上界"；
- [ ] 独立完成打印归档，A4／控件隐藏／内容完整三项全中；
- [ ] 至少记录到一条真实困惑点（一条都没有，通常说明没认真走或你在旁边提示了）。

**任一读者**把 `cannot_be_bounded` 说成"系统失败"→ 不 pass。记录原话，并考虑 V2-D3 的反转条件（把证书表格恢复回首屏）。若累计五名读者多数在 90 秒内答不出，按原计划反转 D3。

## 第 6 步 · 收口（pass 之后才做）

1. 新建 `docs/verification/2026-11-18-v2-reader-gate.md`，写入：读者代号与角色、日期、三道题的原话答案、困惑点、判定勾选表、PDF 归档位置。可用匿名代号，不必写真人姓名，但要能证明"非作者、非同屏作者代操作"。
2. 改 `docs/superpowers/plans/2026-11-17-v2-audience.md` 第 79 行 `V2-B6` 的 verdict 由 `not-run` 改为 `pass`，Reading 列指向上面这份文档。
3. 改 `docs/verification/2026-11-18-v2-reader-walkthrough.md`：开头的 "B6 stays not-run"、§4 的 B6 行、§2 "To close" 段落，同步为已关闭并链接到新文档。B6′ 行保持 agent-only 不变。
4. 若判定为不 pass：不要改任何门禁行；把困惑点写进新文档，回到 V2-D3 反转决策。

## 已知边界（写进记录时别漏）

- 现有语料每个证书都是 `empty_feasible_set`，所以任何合式 claim 都只能得到 `cannot_be_bounded`；`bounded_supports` / `bounded_refutes` 两个 verdict **本次无法用真人验证**，需要另一个发布过认证比率的包。
- 本次验证的是局域网上的 SQLite 部署；非 SQLite 后端、公网部署不在 B6 范围内。

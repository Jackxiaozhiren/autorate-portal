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

## 第 1 步 · 准备环境（约 2 分钟）

一条命令把库、演示包和两张令牌都准备好：

```bash
cd /Users/jackson/laya/autorate-portal
.venv/bin/python tools/walkthrough.py up
```

它做四件事，然后把结果打印出来：用**测试夹具本身**构建 M4 演示包（与套件断言的是同一个文件，
不会各自漂移）、按**迁移链**建库、摄入这个包、给 P1/P2 各签一个令牌。打印内容包括：

- 起服务的命令（含库路径、盐、密钥、端口、`--store`）；
- 读者要打开的地址（自动取 `en0`/`en1` 的内网 IP，取不到则为 `127.0.0.1`）；
- 两张令牌卡，形如 `P1 (compliance, ada@example.test): <token>`。

令牌同时写进 `/tmp/v2-walkthrough/tokens.json`（权限 `0600`）。换端口或换目录用
`--port 8123 --root /tmp/other`；库已存在时会拒绝覆盖，确认重来再加 `--reset`。

**1.1 在另一个终端，按它打印的那行命令起服务。** 关键是 `--host 0.0.0.0`：绑 `127.0.0.1`
读者连不上。若打印的地址不是读者能访问的那个（多网卡、VPN、手机热点），用 `--address` 覆盖。

**1.2 别人坐下之前，先自己跑一遍预检**：

```bash
.venv/bin/python tools/walkthrough.py check
```

它**以读者身份**做同样的十件事——P1/P2 各登录一次、各读一次证书列表、各问三道题——逐行打印
`ok` / `FAIL`。十行全 `ok` 才发题；任何一行 `FAIL` 都说明库不对，现在发现只是返工，读者坐下之后
才发现就是白跑一趟。它连不上服务会直接说 `start the service first`，不会假装通过；缺令牌、令牌
签错了盐、库没摄入，各有各的那一行变红（见下表）。

| `check` 的某行变红 | 通常意味着 |
|---|---|
| `P1/P2 sign-in` | 令牌不是这个盐签的，或库不是这个库 |
| `P1/P2 certificates` | 库里没有证据：`up` 是否报过 `refused`？摄入是否跳过？ |
| `P1/P2 Q1-Q3` | 语料或判定逻辑变了，先别发题——跑一遍套件 |

**1.3 把两张卡分别给两个人**：P1 的只给 P1，P2 的只给 P2。**不要**把你自己的令牌给他们，也不要
让他们共用一个——审计日志要能区分谁做了什么。

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
2. 改 `docs/superpowers/plans/2026-11-17-v2-audience.md` 里 `V2-B6` 那一行的 verdict 由 `not-run` 改为 `pass`，Reading 列指向上面这份文档（按行号找会失效，按 `V2-B6` 找）。
3. 改 `docs/verification/2026-11-18-v2-reader-walkthrough.md`：开头的 "B6 stays not-run"、§4 的 B6 行、§2 "To close" 段落，同步为已关闭并链接到新文档。B6′ 行保持 agent-only 不变。
4. 若判定为不 pass：不要改任何门禁行；把困惑点写进新文档，回到 V2-D3 反转决策。

## 已知边界（写进记录时别漏）

- 现有语料每个证书都是 `empty_feasible_set`，所以任何合式 claim 都只能得到 `cannot_be_bounded`；`bounded_supports` / `bounded_refutes` 两个 verdict **本次无法用真人验证**，需要另一个发布过认证比率的包。
- 本次验证的是局域网上的 SQLite 部署；非 SQLite 后端、公网部署不在 B6 范围内。
- `cannot_be_bounded` 对"这个包没测过这个字段"和"这个库里没有任何证书"是**同一个答案**。二者只能靠
  证书行数分辨，这就是 `check` 数证书的原因。若 `certificates` 行是 `0`，先回头看 `up` 有没有报
  `the demo packet was refused`，不要当成"项目还没有数据"。
- `up` 用迁移链建库，所以 `/readyz` 会答 `ready` 并报出 revision。若你换了库却看到
  `schema-missing`，那是库没经过迁移，不是服务坏了。
- `check` 只覆盖 P1/P2 的三道题与登录路径；它不检查打印版式（A4、控件隐藏），那三项只能在读者的
  打印预览里看，仍按第 4 步记录。

## 附录 · 工具不可用时的手工版

`tools/walkthrough.py` 依赖 `.venv` 与 `tests/conftest.py`（演示包用夹具本身构建，手抄一份就是第二个
真相）。演示包这一步没有手工替代：

```bash
.venv/bin/python tools/walkthrough.py packet --out /tmp/v2-walkthrough/demo.packet.tar
```

其余步骤可以手工等价地做：

```bash
cd /Users/jackson/laya/autorate-portal
.venv/bin/python - <<'PY'
from pathlib import Path
from autorate_portal import auth, db, ingest, migrate

url = "sqlite:////tmp/v2-walkthrough/portal.db"
migrate.upgrade_to_head(url)      # 不要用 create_all：那会让 /readyz 报 schema-missing
S = db.make_session(db.make_engine(url))

with S() as s:                    # 组织、项目、三个用户
    s.add(db.Org(id="org-laya", name="org-laya"))
    s.add(db.Project(id="prj-laya", org_id="org-laya", name="laya autorate"))
    for uid, mail, role in (("u-ada", "ada@example.test", "compliance"),
                            ("u-lin", "lin@example.test", "viewer"),
                            ("u-prod", "producer@example.test", "producer")):
        s.add(db.User(id=uid, email=mail, display=mail.split("@")[0]))
        s.add(db.Membership(user_id=uid, org_id="org-laya", role=role))
    s.commit()

with S() as s:                    # 摄入演示包
    r = ingest.ingest(s, bundle_path=Path("/tmp/v2-walkthrough/demo.packet.tar"),
                      project_id="prj-laya", actor="producer@example.test",
                      store_dir=Path("/tmp/v2-walkthrough/store"))
    s.commit()
    print(r.state, r.accepted)    # 必须是 accepted True

with S() as s:                    # 一位读者一个令牌
    for label, uid in (("P1", "u-ada"), ("P2", "u-lin")):
        tok, _ = auth.issue_token(s, user_id=uid, project_id="prj-laya",
                                  salt="walkthrough-salt")
        print(f"{label} ({uid}): {tok}")
    s.commit()   # 必须：issue_token 只 flush，不 commit 会在上下文退出时回滚
PY
```

`issue_token` 只 `flush()` 不提交：省略 `s.commit()` 会回滚，令牌打印出来了却落不了库，用它得到
`401 unknown token`。本次走查踩过并修正。

手工版不会替你写令牌文件。把打印出的两个令牌按 `{"P1": "...", "P2": "..."}` 存进
`/tmp/v2-walkthrough/tokens.json`，`check` 默认就从这里读；不存也能走完第 2 步，但第 1.2 步的预检
就没人替你做了。

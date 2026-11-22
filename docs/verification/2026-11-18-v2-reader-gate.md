# V2 external reader gate — 待填写

> 状态：**草稿，未生效**。本文件在两名非作者真人完成走查并填写下方记录后才成为门禁证据。
> 在此之前，`V2-B6` 保持 `not-run`，不得引用本文件将其改为 pass。
> 执行手册：`docs/verification/v2-reader-gate-runbook.md`。

## 环境与参与者

- 服务：`http://172.20.10.5:8111/`（绑定 `0.0.0.0:8111`，SQLite 走查库，schema-2 包 `pkt-ce1271fa3bdef759`）
- 走查日期：____（待填）
- 组织者：____（作者本人，**不**参与答题、不提示）
- 两名读者（均为非作者、未看过源码）：

| 代号 | 角色 | 姓名/工号（可匿名） | token 已单独发放 |
|---|---|---|---|
| P1 | 合规 | ____ | ☐ |
| P2 | 采购/业务 | ____ | ☐ |

## 逐人记录（照抄手册第 4 步的表格）

### P1

```
Q1 判断（成立/不成立/无法判断）：____________________
   Q1 用自己的话解释结果：__________________________
   从看到页面到作出判断耗时：____ 秒
Q2 判断 + 复述：____________________________________
Q3 判断 + 复述：____________________________________
打印：A4？□是 □否  控件隐藏？□是 □否  结果与理由完整？□是 □否
PDF 位置：__________________________________________
卡住的地方（原话）：______________________________
没看懂的词（原话）：______________________________
```

### P2

```
Q1 判断（成立/不成立/无法判断）：____________________
   Q1 用自己的话解释结果：__________________________
   从看到页面到作出判断耗时：____ 秒
Q2 判断 + 复述：____________________________________
Q3 判断 + 复述：____________________________________
打印：A4？□是 □否  控件隐藏？□是 □否  结果与理由完整？□是 □否
PDF 位置：__________________________________________
卡住的地方（原话）：______________________________
没看懂的词（原话）：______________________________
```

## 判定（两名读者都满足才打勾）

- [ ] Q1 在 90 秒内给出判断
- [ ] 把 `cannot_be_bounded` 理解为"结果/本项目未对此认证"，而非"系统故障"
- [ ] Q2 没有编造或寻找一个不存在的数字
- [ ] Q3 能区分"输入错误"与"无法给出上界"
- [ ] 独立完成打印归档，A4／控件隐藏／内容完整三项全中
- [ ] 至少记录到一条真实困惑点

综合 verdict（待填）：`pass` / `not-pass` ____

## 若 pass，收口动作（逐项勾选后才算关闭）

- [ ] 填妥上方全部记录与判定
- [ ] 改 `docs/superpowers/plans/2026-11-17-v2-audience.md` 第 79 行 `V2-B6`：`not-run` → `pass`，Reading 指向本文件
- [ ] 改 `docs/verification/2026-11-18-v2-reader-walkthrough.md`：开头 "B6 stays not-run"、§4 B6 行、§2 "To close" 段落，同步为已关闭并链接本文件（B6′ 行保持 agent-only）
- [ ] 删除本文开头的"草稿，未生效"提示

## 若 not-pass

不改任何门禁行，保持 `V2-B6 = not-run`。把困惑点原话写入本文件，回到 V2-D3 反转决策（恢复证书表格前置）。

## 附件 A：ego-browser 机器代理走查（2026-11-20，非真人，不关闭 B6）

`ego-browser` skill（v2.2.1）具备完整浏览器控制能力：TaskSpace/Page API，
`goto/fill/click/selectOption/waitForSelector/waitForFunction/evaluate/screenshot/mouse.wheel/cdp` 全部可用。
用它按真人路径走了一遍（space 2，127.0.0.1:8111，P1 token）：

| 步骤 | 操作 | 结果 |
|---|---|---|
| A1 | 打开首页取语义快照 | 全 DOM 可读：语言下拉、token 框、Sign in、claim 表单、证书表标题；首屏 claim 在表格之前 |
| A2 | 填 token、点 Sign in | token 框清空，证书表自动加载 7 行（含 1 个 `statistically feasible`） |
| A3 | Q1 默认 confidence，点 Check a claim | `cannot_be_bounded`，理由"packet never measured 'confidence'"，逐字引用与来源标注齐全；截图 `q1-verdict.png` 视觉确认：文字清晰、无重叠截断 |
| A4 | Q2 字段改 autorate | `cannot_be_bounded`，理由"no certificate publishes a certified autorate"——与 Q1 不同，是真实计算 |
| A5 | Q3 清空字段 | 错误 `a claim needs share, field, unit and population; missing: field` |
| A6 | 切简体中文 | 全界面切中文；intro 为"'无法给出上界'是结论，不是故障" |
| A7 | 鼠标滚轮向下 | scrollY 0→484，证明可真实滚动 |
| A8 | `Emulation.setEmulatedMedia=print` | `.row` display:none、`body max-width:none`；打印截图 `print-preview.png` |
| A9 | 点退出 | token 框清空、证书表 hidden=true |

### 本次走查发现的两个真实缺陷（2026-11-21 已修复并复核）

1. **打印在深色系统偏好下不可读（严重，影响 V2-D4）。** 系统 `prefers-color-scheme: dark` 时，
   打印媒体下计算样式为 `body color=rgb(255,255,255)`、`color-scheme=light dark`；打印 CSS 未覆盖
   文字/背景色，A4 白纸上会印出白字。修复方向：`@media print` 内显式设
   `color-scheme: light; body { background:#fff; color:#000 }`，并去掉 `.banner` 里依赖深色的边框色假设。
2. **claim 校验错误未本地化（中等）。** 在 `lang=zh-Hans` 下提交空字段，错误仍为英文
   `a claim needs share, field, unit and population; missing: field`。大部分文案已双语，
   这一条错误路径漏了 i18n；`tests/test_first_screen.py` 只查了静态文案，未覆盖运行时校验错误。

两者都是机器可复现的确定性缺陷，与"真人能否理解"无关，因此不写入读者困惑点，也不影响 B6 verdict
（B6 仍 `not-run`）。但它们说明：即使没有真人读者，可视层走查仍有发现产品缺陷的价值，
应作为常规 QA 保留，而非用 HTTP probe 替代。

### 缺陷 1 的修复与复核

`src/autorate_portal/web/index.html` 的 `@media print` 现在先关掉跟随系统的配色，再显式给纸面颜色：

```css
@media print {
  :root { color-scheme: light; }
  html, body { background: #fff; color: #000; }
  .muted, .triple { color: #444; }        /* #8888 在纸上过淡 */
  tbody tr:hover { background: transparent; }
  /* A4、隐藏控件、break-inside 保持不变 */
}
```

自包含文档（`packet html` / share link）本来就有 `color-scheme:light` 与 `color:#1f2328;background:#fff`，
无此缺陷；本次只改了门户页。

复核（ego-browser，`Emulation.setEmulatedMedia` 强制 `media=print` + `prefers-color-scheme=dark`）：

| 读数 | 修复前 | 修复后 |
|---|---|---|
| `documentElement.colorScheme` | `light dark` | `light` |
| `body backgroundColor` | 深色画布 | `rgb(255, 255, 255)` |
| `body color` | `rgb(255, 255, 255)` | `rgb(0, 0, 0)` |
| `.muted color` | `#8888` | `rgb(68, 68, 68)` |
| 表格单元格 color | 随主题 | 全部 `rgb(0, 0, 0)`、opacity 1 |
| 控件 `.row` | `display:none` | `display:none` |

浅色偏好下打印态同样为 `rgb(255,255,255)` / `rgb(0,0,0)`，无回归。打印截图：`/tmp/v2-walkthrough/print-fixed.png`。

### 缺陷 2 的修复与复核

错误文案改为数据而非固定英文句子：`ClaimError` 现在携带 `missing` 字段元组，并提供
`localized(locale)`；HTTP 层用它渲染 422 的 `detail`。字段名复用既有 `label.share|field|unit|population`，
列表分隔符也进目录（`punct.list_separator`：en `", "`，zh `"、"`）。`str(exc)` 仍是英文，
CLI 与不传 locale 的 token API 措辞不变。

复核：

| 路径 | 读数 |
|---|---|
| `POST /api/v1/claims/check?locale=zh-Hans`，`{"share":"0.66"}` | 422 `声明需要份额、字段、单位和总体；缺少：字段、单位、总体` |
| 同请求 `locale=en` | 422 `a claim needs share, field, unit and population; missing: field, unit, population` |
| 浏览器 UI（zh-Hans，清空 field 提交） | `#error` 显示上句中文；按钮为"核查声明" |
| 走查脚本 11 步 | 与修复前逐项一致（401/200/403/200/200/422/200/200/200/401/200），`failures: None` |

回归测试新增 2 条：`tests/test_print_view.py::test_the_portal_print_sheet_does_not_inherit_a_dark_screen_preference`
与 `tests/test_api_claims_exports.py::test_a_partial_claim_refusal_speaks_the_locale_it_was_asked_in`。
完整套件 **376 passed, 1 warning**。

> 注意：`ego-browser` 是机器代理。它能执行点击/输入/滚动/截图，也能读语义 DOM，但**不能**回答
> "一个非作者会不会把 cannot_be_bounded 误读成故障"——它没有预期、不会被措辞困惑。B6 保持 `not-run`。

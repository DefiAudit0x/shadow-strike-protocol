# Shadow Strike Protocol

> مختبر محاكاة هجمات تفاعلي للعقود الذكية — يحوّل الفرضية الأمنية إلى هجوم
> منفَّذ فعلياً، يُثبت عبر state transitions حقيقية، لا بتخمين من نموذج لغوي.

هذا تطبيق فعلي، يعمل، للأرشيتكتشر الموصوف في `ARCHITECTURE.md`. تم بناؤه
بمبدأ واحد صارم: **الـ reasoning (LLM) لا يقرر أبداً إن نجح الهجوم —
الـ execution + الـ verification الحتمي هما من يقرران.**

## التشغيل الفوري (بدون أي تثبيت)

المحرك الأساسي يعمل بدون أي dependency خارجي باستثناء `jinja2` و`pyyaml`
(كلاهما شائع ومتوفر غالباً بالفعل). لا حاجة لـ Foundry أو RPC أو مفتاح API
لتجربة الـ pipeline كاملاً:

```bash
pip install -r requirements.txt   # jinja2 + pyyaml فقط
PYTHONPATH=. python3 examples/run_demo.py
```

هذا ينفّذ، فعلياً، لا نظرياً:

1. **Recon** حقيقي على `contracts/src/Vault.sol` (عقد فيه ثغرة reentrancy حقيقية)
2. **Hypothesis generation** قائم على أنماط مكتبة الهجمات (`attack_library/`)
3. **بناء AttackScenario** مُتحقَّق منه بالكامل (Pydantic-style validation)
4. **تنفيذ فعلي** للهجوم عبر محاكي EVM مصغّر (`MockExecutor`) — ليس ادعاءً،
   بل ledger حقيقي للـ ETH مع دلالات reentrancy صحيحة
5. **توليد Foundry test حقيقي** (`.t.sol`) من نفس الـ scenario بالضبط —
   جاهز للتشغيل بـ `forge test` بمجرد توفر Foundry + RPC
6. **Verification** حتمي عبر `safe_eval` (ليس `eval()` الخطير)
7. **تخزين الإثبات** في Knowledge Store (SQLite)
8. **إعادة نفس السيناريو بالضبط** ضد `SafeVault` (النسخة المُصلَحة) لإثبات
   أن الإصلاح يصمد — `ATTACK FAILED` هنا هو النتيجة المطلوبة

```bash
PYTHONPATH=. python3 -m unittest discover -s tests -v   # 19 اختبار، كلها تمر
PYTHONPATH=. python3 -m shadow_strike.cli library        # عرض مكتبة الهجمات
```

## البنية

```
shadow_strike/
├── core/            # AttackScenario schema + safe_eval (zero deps)
├── attack_library/  # plugins: reentrancy (كامل), access_control (كامل),
│                     #          oracle_manipulation / flash_loan (roadmap)
├── execution/
│   ├── compiler.py          # Scenario -> Foundry .t.sol حقيقي
│   ├── foundry_runner.py    # تنفيذ إنتاجي حقيقي (يتطلب forge + RPC)
│   └── mock_executor.py     # تنفيذ فوري بدون شبكة (للتطوير/العرض/CI)
├── verifier/        # القاضي الحتمي — لا LLM هنا إطلاقاً
├── storage/         # Knowledge Store (SQLite هنا، Postgres في الإنتاج)
├── agent/
│   ├── nodes.py             # العقد الستة: recon/hypothesis/planner/
│   │                         # executor/verifier/critic
│   ├── graph_simple.py      # منسّق بدون dependencies — يعمل الآن
│   └── graph_langgraph.py   # نسخة LangGraph الإنتاجية (pip install langgraph)
├── api/main.py      # FastAPI (pip install fastapi uvicorn)
└── cli.py

contracts/
├── src/Vault.sol              # الهدف الضعيف (reentrancy حقيقي)
├── src/SafeVault.sol          # نفس الواجهة، مُصلَح
├── src/attackers/             # عقد المهاجم (يدوي + نسخة مولَّدة)
└── test/                       # Foundry tests (يدوي + مولَّد تلقائياً)
```

## ما اكتمل منذ النسخة الأولى

| العنصر | الحالة |
|---|---|
| 11/11 نوع ثغرة في مكتبة الهجمات | مسجَّلة؛ 7 منها (`reentrancy`, `access_control`, `oracle_manipulation`, `flash_loan`, `price_manipulation`, `signature_replay`, `initialization`) لها attacker template تنفيذي؛ 4 (`accounting`, `upgradeability`, `cross_contract`, `economic`) موثقة كـ roadmap مع تبرير معماري صريح لماذا لا يمكن تعميمها |
| `oracle_manipulation` حي | `SimplePool` + `OracleFedLendingMarket` + `OracleManipulationAttacker` في `mock_executor.py` — هجوم تلاعب بالسعر فعلي ومُختبَر (pool رقيق يُستغل، pool عميق يصمد) |
| `access_control` حي | `AccessControlTarget` — حارس مكسور يُستغل، حارس مُفعَّل يصدّ الهجوم |
| Sandboxing حقيقي | `execution/sandbox.py` — حدود CPU/ذاكرة عبر `resource.setrlimit`، مُختبَرة حياً (عملية runaway تُقتل فعلياً)؛ + `docker/sandbox.Dockerfile` للعزل الكامل بالحاويات |
| `state_diff` حقيقي | `compiler.py` يُولّد `vm.record()`/`vm.accesses()` (cheatcodes حقيقية من forge-std)، `foundry_runner.py` يفكّك الناتج |
| ربط LLM حقيقي | `agent/llm_providers.py` — `AnthropicLLM` (stdlib فقط، بلا SDK) جاهز لمفتاح API حقيقي؛ `EchoLLM` للاختبار بدون شبكة (مُختبَر حياً) |
| ربط DeFiAudit | `reporting/report_generator.py` — يحوّل أي proof إلى Markdown finding بصيغة تدقيق احترافية (مُختبَر حياً، انظر المثال في `examples/run_demo.py` الخطوة 10) |
| Postgres للإنتاج | `storage/postgres_store.py` — نفس واجهة `KnowledgeStore` بالضبط (drop-in) + `migrate_from_sqlite()` |

**ملاحظة صدق مهمة**: العناصر التالية مكتوبة ومفحوصة بنيوياً (`py_compile`) لكن **غير مُختبَرة حياً** في هذه البيئة لأنها تحتاج شبكة/dependencies غير متوفرة هنا: `AnthropicLLM` (يحتاج مفتاح API حقيقي)، `postgres_store.py` (يحتاج `sqlalchemy`+Postgres)، `api/main.py` (يحتاج `fastapi`)، تفاصيل `foundry_runner.py` الدقيقة لتنسيق `--json` (تحتاج Foundry حقيقياً — الشكل العام موثق لكن إصدارات forge المختلفة قد تغيّر شكل الـ JSON قليلاً، فاختبره أول استخدام).

## ما اكتمل في هذه الجولة (packaging + CI + التأليف اليدوي)

| العنصر | الحالة |
|---|---|
| `pyproject.toml` | حزمة Python حقيقية، **مُختبَرة حياً**: `pip install -e .` نجح، وأمر `shadow-strike library` اشتغل من مجلد `/tmp` (خارج مجلد المشروع تماماً) — إثبات أن الـ packaging سليم فعلياً |
| `.github/workflows/ci.yml` | 4 jobs: اختبارات على 3.10/3.11/3.12، lint، Foundry tests محلية (بدون fork — تعمل حتى من forks)، فحص استيراد الوحدات الإنتاجية |
| `Makefile` | `make test` / `make demo` / `make sandbox-selftest` — **مُختبَرة حياً** |
| **التأليف اليدوي للسيناريوهات (`core/scenario_loader.py`)** | هذا هو المسار الفعلي لأنواع `accounting`/`upgradeability`/`cross_contract`/`economic` التي لا بانٍ تلقائي لها: تكتب السيناريو بصيغة YAML، يمر بنفس تحقق `AttackScenario` بالضبط، ثم يشتغل بنفس الـ pipeline. **مُختبَر حياً بالكامل**: `shadow-strike run-scenario --file examples/scenarios/reentrancy_demo.yaml` نفّذ الهجوم وتحقق منه عبر الأمر المثبَّت فعلياً؛ `shadow-strike save-scenario` صدّر النتيجة رجوعاً كـ YAML قابل للتعديل |
| `dashboard/index.html` | واجهة مراقبة/تشغيل بسيطة تستهلك `api/main.py` — بدون build step، بدون CDN خارجي. **غير مُختبَرة حياً** (تحتاج `uvicorn` يعمل فعلياً) |

```bash
# أي باحث يضيف سيناريو يدوي لنوع ثغرة بلا builder تلقائي:
shadow-strike run-scenario --file my_scenario.yaml --engine mock \
    --mock-kinds vault=VulnerableVault --mock-kinds attacker=ReentrantAttacker
```

## 11/11 — كل نوع ثغرة صار له إثبات تنفيذ حي الآن

أضفت 3 أمثلة مكتوبة يدوياً تغطي آخر 3 أنواع كانت roadmap بالكامل:

- **`cross_contract`**: `TrustingRouter` يسمح لأي حد يغيّر "العقد الموثوق" اللي يستشيره للتفويض — المهاجم يحوّل الثقة لعقد يتحكم فيه، يصرّح لنفسه بأي مبلغ. مُختبَر حياً بما فيها حالة "لو ما كان فيه hijack، العقد الشرعي كان يرفض نفس الطلب".
- **`upgradeability`**: `VulnerableProxy` بدون access control على `upgradeTo()` + تصادم storage حقيقي — implementation خبيث يكتب فوق slot الـ owner مباشرة. مُختبَر حياً.
- **`economic`**: `SelfLiquidationMarket` — bonus تصفية سخي جداً يخلي المهاجم يصفّي مركزه الخاص بربح، بدون أي تلاعب سعر أو ثغرة كود، مجرد رياضيات الحوافز. **لقيت وأصلحت bug اقتصادي ثالث هنا بالتشغيل الفعلي**: أول نسخة كانت تحدّ الـ payout بسقف collateral المهاجم نفسه، وهذا يخلي الربح الحقيقي مستحيل رياضياً مهما كان الـ bonus كبير — صلّحتها (الحد الحقيقي لازم يكون سيولة البروتوكول، مو رأسمال المهاجم نفسه)، وأثبتّ النسختين: bonus سخي (20%) = ربح فعلي، bonus محافظ (5%) = خسارة فعلية.

النتيجة: **كل الـ11 نوع (مش بس الـ7 اللي عندهم builder تلقائي) عندهم الآن إثبات تنفيذ حي مُختبَر** — الفرق الوحيد إن الـ4 أنواع دي تمر عبر مسار التأليف اليدوي (YAML) بدل البناء التلقائي، وهذا مطابق تماماً لتصميم الأرشيتكتشر الأصلي.

## flash_loan وaccounting — آخر فجوتين

- **`flash_loan` صار حي بالكامل** — مش builder مستقل (مصمَّم عمداً إنه يتركّب مع نوع ثاني، شوف `composes_with` في الـ meta.yaml)، لكن الآن عندي `MockFlashLender` + `FlashLoanReentrantAttacker` حقيقيين: مهاجم **برأس مال صفر** يقترض عبر flash loan، يدخل بنفس نمط الـ reentrancy، يسدد القرض + العمولة، ويطلع بربح صافي. مُختبَر حياً بما فيها حساسية العمولة (عمولة أعلى = ربح أقل، فحصتها رقمياً). كل الـ7 أنواع اللي عندها template صار عندها تنفيذ حي الآن (7/7).
- **مثال عملي لـ `accounting`** — هذا النوع ما له builder تلقائي عمداً (الأرشيتكتشر يقول صراحة إن أخطاء المحاسبة خاصة بكل بروتوكول). بدل ما أسيبه نظري بالكامل، بنيت مثال مكتوب يدوياً: `UncheckedBalanceToken` — bug حقيقي (uint256 underflow من عملية `unchecked`)، مهاجم بصفر توكنات يحوّل أكثر من رصيده فيطفح الرصيد لـ 2^256 بالضبط. مُختبَر حياً، بما فيها النسخة المُصلَحة (checked=True) اللي ترفض العملية بدل ما تطفح.

## تنظيف ما بعد الأفكار الخمس

- **`signature_replay` و`price_manipulation` أصبحا حيين** (كان عندهم template بس بدون mock) — الآن 6 من أصل 7 أنواع مُشفّرة لها تنفيذ حي ومُختبَر (الوحيد الناقص: `flash_loan`، لأنه composable مع غيره حسب تصميمه الأصلي).
- **bug حقيقي ثاني انكشف بالتشغيل الفعلي**: أول نسخة من سيناريو `price_manipulation` كانت تفحص `total_shares` فور هجوم المهاجم نفسه — وهذا ما يميّز فعلياً بين vault ضعيف وآخر محصّن (الاثنين يبدآن قريب من صفر بعد إيداع صغير واحد). الإصلاح: إضافة خطوة إيداع "ضحية" بعد التلاعب، وفحص حصتها هي — هذا هو التوقيع الحقيقي للاستغلال.
- **تكرار كود حقيقي انكشف واتنظّف**: لقيت نسختين متوازيتين من نفس المنطق (`SignatureReplayTarget`/`ShareVault` مقابل `SignedActionTarget`/`ERC4626LikeVault`) بأسماء مختلفة في نفس الملف — دمجتهم لنسخة واحدة مُختبَرة، وحذفت ملف الاختبار اليتيم المرتبط بالنسخة المحذوفة.
- **`/benchmark` و`/sentinel/hypothesis`** أُضيفا لـ `api/main.py` — الـ API الآن يغطي كل الأفكار الخمس، مو بس التشغيل العادي.
- **`CONTRIBUTING.md`** — دليل كامل لإضافة نوع ثغرة جديد، خطوة بخطوة.
- **`CHANGELOG.md`** — سجل كامل لرحلة البناء، صادق بالتمييز بين "مُختبَر حياً" و"مكتوب بس يحتاج بنية تحتية".

## الأفكار الخمس (من نقاش roadmap لاحق) — كلها مبنية ومُختبَرة حياً الآن

| الفكرة | أين | الحالة |
|---|---|---|
| **1. حوادث تاريخية حقيقية** | `examples/historical_incidents/` | 3 حوادث (The DAO, Parity Multisig freeze, Mango Markets) معاد بناؤها كسيناريوهات YAML و**مُتحقَّق منها حياً**. تحذير صادق مكتوب بوضوح: إعادة بناء مبسّطة من post-mortems عامة، مش replay حرفي لنفس الـ bytecode. Mango تحديداً مُعلَّم بوضوح إنه كان على Solana لا EVM |
| **2. تكامل Axiom/Sentinel** | `shadow_strike/integrations/axiom_adapter.py` | واجهة Python نظيفة (`handle_sentinel_request`) — بمسارين: فرضية محددة من Sentinel، أو benchmark كامل لو ما عنده فرضية. **مُختبَرة حياً** بالمسارين. غير مربوطة بكود Axiom الفعلي (مش متوفر هنا) لكن العقد (contract) جاهز |
| **3. مراقبة مستمرة** | `shadow_strike/monitoring/watcher.py` | منطق الـ dispatch/alert/regression-detection **مُختبَر حياً بالكامل** (synthetic events) — بما فيها اكتشاف أن upgrade رجّع ثغرة كانت مُصلَحة. أما الاستطلاع الفعلي على السلسلة (`EVMChainWatcher.poll`) فهو interface موثّق فقط، يرمي `NotImplementedError` بتوضيح صريح ليش (يحتاج RPC + web3.py حقيقيين) |
| **4. Benchmark/scorecard** | `shadow_strike/benchmark/runner.py` | يجرّب كل نوع ثغرة تطابقه الـ heuristics بشكل مستقل، وينتج scorecard. **مُختبَر حياً** ضد عقد فيه نوعان من الثغرات معاً في نفس الوقت |
| **5. مقال تقني** | `BLOG_POST.md` | مقال كامل جاهز للنشر (بالإنجليزية — افتراض بناءً على جمهورك الدولي على LinkedIn/Kaggle؛ قولّي لو تبيه بالعربي) |

## الترقية إلى الإنتاج الكامل

كل مكوّن "خفيف" هنا له بديل إنتاجي موثَّق داخل الكود نفسه (docstring في
أعلى كل ملف يشرح الفرق بالضبط):

| هنا الآن (zero-dep) | الإنتاج |
|---|---|
| `dataclasses` في `core/models.py` | Pydantic v2 (JSON schema export) |
| `MockExecutor` | `ForgeRunner` (حقيقي، يتطلب Foundry + RPC + sandboxing) |
| `SimpleShadowStrikeGraph` | `graph_langgraph.py` (checkpointing, streaming) |
| SQLite | Postgres (نفس الـ schema بالضبط) |
| hypothesis/critic قائمين على heuristics | ربط `llm_fn` بأي عميل LLM حقيقي |

```bash
# لتشغيل ضد Foundry حقيقي بمجرد توفره:
forge install foundry-rs/forge-std
export MAINNET_RPC_URL=https://...
python3 -m shadow_strike.cli run \
    --source contracts/src/Vault.sol --protocol MyVault \
    --target vault=0xRealAddress --fork-url $MAINNET_RPC_URL \
    --fork-block 19000000 --engine foundry
```

## تحذير أخلاقي وقانوني

كل عقد مولَّد يحمل تعليقاً صريحاً: **لا تُشغّل أي سيناريو هنا ضد بروتوكول
حقيقي لا تملكه أو لا تملك تفويضاً خطياً لاختباره.** هذا مختبر بحث أمني؛
استخدامه خارج نطاق fork محلي/testnet/تفويض صريح من البروتوكول المستهدف
يخرج عن الغرض الذي بُني من أجله بالكامل.

## التفاصيل المعمارية الكاملة

انظر `ARCHITECTURE.md` للأرشيتكتشر الكامل (17 قسماً)، بما فيها خارطة
الطريق للمراحل القادمة (plugins إضافية لـ oracle manipulation وflash loan،
sandboxing كامل عبر Docker، ربط مباشر بـ DeFiAudit).

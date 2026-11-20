# Shadow Strike Protocol — Full System Architecture

> مختبر محاكاة هجمات تفاعلي للعقود الذكية — يحوّل الفرضية الأمنية إلى هجوم قابل للتنفيذ، يُثبت بـ state transitions فعلية على EVM، لا بتخمين من نموذج لغوي.

---

## 0. مبادئ التصميم (Design Principles)

هذه المبادئ تحكم كل قرار معماري لاحق، ويجب ألا تُخترق مهما كانت الإضافة مغرية:

1. **Separation of Concerns الصارم**: Reasoning (LLM) ≠ Execution (Foundry/EVM) ≠ Verification (Proof Engine). لا يلتقي الثلاثة في مكون واحد أبداً.
2. **لا حُكم بدون دليل**: أي "نجاح" للهجوم يجب أن يُشتق من state diff + trace فعليين، لا من نص يولّده LLM.
3. **Scenario كبيانات، لا كسكريبت حر**: كل سيناريو هجوم هو كائن Pydantic منظم وقابل للتسلسل (serializable)، وليس كود Python عشوائي.
4. **Determinism في طبقة التنفيذ**: نفس الـ scenario + نفس fork block يجب أن يعطي نفس النتيجة دائماً (fixed seed، fixed block number، fixed timestamp).
5. **Composability**: كل عنصر (hypothesis generator، executor، verifier) يجب أن يُستبدل منفرداً دون كسر الباقي.
6. **Everything is an artifact**: كل محاولة، ناجحة أو فاشلة، تُخزَّن كمعرفة قابلة لإعادة الاستخدام.

---

## 1. نظرة عامة على المعمارية (High-Level Architecture)

```
┌─────────────────────────────────────────────────────────────────────┐
│                           CLIENT LAYER                                │
│        CLI  /  Web Dashboard  /  API (REST + WebSocket for streaming) │
└───────────────────────────────┬───────────────────────────────────────┘
                                 │
┌───────────────────────────────▼───────────────────────────────────────┐
│                        ORCHESTRATION LAYER                            │
│                     (FastAPI + Job Queue + State Store)               │
└───────┬─────────────────────┬──────────────────────┬──────────────────┘
        │                     │                      │
┌───────▼───────┐     ┌───────▼────────┐     ┌───────▼────────┐
│  Scenario      │     │   Agent Layer   │     │  Knowledge      │
│  Engine        │◄────┤   (LangGraph)   │────►│  Store          │
│  (Pydantic)    │     │   Reasoning     │     │  (Postgres)     │
└───────┬───────┘     └───────┬────────┘     └─────────────────┘
        │                     │
        │              ┌──────▼───────┐
        │              │ Hypothesis   │
        │              │ Generator    │
        │              └──────┬───────┘
        │                     │
┌───────▼─────────────────────▼───────────────────────────────┐
│                      EXECUTION ENGINE                         │
│   Scenario Compiler → Foundry Test Synthesizer → forge test   │
│                        │                                       │
│                        ▼                                       │
│                   Anvil (forked EVM)                           │
└───────┬─────────────────────────────────────────────────────┘
        │
┌───────▼───────────────────────────────────────────────────────┐
│                     OBSERVATION LAYER                           │
│         State Diff Extractor  │  Trace Parser (call tree)       │
└───────┬───────────────────────────────────────────────────────┘
        │
┌───────▼───────────────────────────────────────────────────────┐
│                       VERIFIER / PROOF ENGINE                   │
│   Invariant Checker → Success Condition Evaluator → Verdict     │
└───────┬───────────────────────────────────────────────────────┘
        │
   ┌────▼────┐
   │ SUCCESS │────► Proof Artifact ──► Attack Library (indexed)
   └────┬────┘
        │
   ┌────▼────┐
   │ FAILURE │────► Critic Node (LangGraph) ──► Refine ──► Retry (bounded)
   └─────────┘
```

---

## 2. الطبقات بالتفصيل

### 2.1 Scenario Engine (طبقة البيانات)

هذه الطبقة هي "العقد" (contract بمعنى interface) بين كل المكونات الأخرى. كل شيء يمر منها.

**النموذج الأساسي (Pydantic v2):**

```python
from pydantic import BaseModel, Field, field_validator
from enum import Enum
from typing import Literal

class AttackerModel(BaseModel):
    address: str
    initial_eth: float = 0
    initial_tokens: dict[str, float] = {}  # token_symbol -> amount
    controlled_contracts: list[str] = []    # e.g. malicious fallback contract

class TransactionStep(BaseModel):
    step_id: int
    caller: str                 # "attacker" | contract address
    target: str                 # contract address or alias
    function: str                # e.g. "withdraw(uint256)"
    args: list
    value_eth: float = 0
    expected_revert: bool = False
    comment: str | None = None

class InitialState(BaseModel):
    fork_url: str                # RPC for forked mainnet/testnet
    fork_block: int               # pinned block for determinism
    target_contracts: dict[str, str]   # alias -> address
    balances: dict[str, float] = {}
    custom_setup_calls: list[TransactionStep] = []

class SuccessCondition(BaseModel):
    expression: str               # e.g. "attacker.eth_balance_after - attacker.eth_balance_before > 0"
    description: str

class VulnerabilityClass(str, Enum):
    REENTRANCY = "reentrancy"
    ORACLE_MANIPULATION = "oracle_manipulation"
    FLASH_LOAN = "flash_loan"
    ACCESS_CONTROL = "access_control"
    PRICE_MANIPULATION = "price_manipulation"
    SIGNATURE_REPLAY = "signature_replay"
    ACCOUNTING = "accounting"
    INITIALIZATION = "initialization"
    UPGRADEABILITY = "upgradeability"
    CROSS_CONTRACT = "cross_contract"
    ECONOMIC = "economic"

class AttackScenario(BaseModel):
    scenario_id: str
    vulnerability_class: VulnerabilityClass
    target_protocol: str
    hypothesis: str                       # النص الذي ولّده الـLLM أو أدخله الباحث
    attacker: AttackerModel
    initial_state: InitialState
    steps: list[TransactionStep]
    assumptions: list[str] = []
    invariants_under_test: list[str] = []  # e.g. "vault.totalAssets >= sum(user.shares)"
    success_conditions: list[SuccessCondition]
    max_retries: int = 3

    @field_validator("steps")
    @classmethod
    def must_have_steps(cls, v):
        if not v:
            raise ValueError("Scenario must have at least one transaction step")
        return v
```

**لماذا هذا مهم معمارياً:** أي سيناريو، سواء أتى من LLM أو من باحث بشري كتبه يدوياً، يمر عبر نفس الـ validation. النظام لا يستطيع تنفيذ سيناريو غير مكتمل أو غير منظم — وهذا يفصل "نية الهجوم" عن "قابلية تنفيذه".

---

### 2.2 Agent Layer (LangGraph)

هذه الطبقة مسؤولة عن الـ reasoning فقط، ولا تلمس EVM مباشرة أبداً.

**الـ State Graph:**

```python
from langgraph.graph import StateGraph, END
from typing import TypedDict

class ShadowStrikeState(TypedDict):
    target_contract_source: str
    recon_notes: str
    hypotheses: list[dict]
    current_scenario: AttackScenario | None
    execution_result: dict | None
    verifier_verdict: dict | None
    attempt_count: int
    history: list[dict]          # كل محاولة سابقة، لإطعامها للـ critic
    final_proof: dict | None

graph = StateGraph(ShadowStrikeState)

graph.add_node("recon", recon_node)
graph.add_node("hypothesis_generator", hypothesis_node)
graph.add_node("scenario_planner", scenario_planner_node)   # يبني AttackScenario Pydantic object
graph.add_node("executor", executor_node)                   # يستدعي Execution Engine (غير LLM)
graph.add_node("verifier", verifier_node)                   # يستدعي Verifier (غير LLM، منطق حتمي)
graph.add_node("critic", critic_node)                        # LLM يحلل سبب الفشل

graph.set_entry_point("recon")
graph.add_edge("recon", "hypothesis_generator")
graph.add_edge("hypothesis_generator", "scenario_planner")
graph.add_edge("scenario_planner", "executor")
graph.add_edge("executor", "verifier")

graph.add_conditional_edges(
    "verifier",
    lambda state: "success" if state["verifier_verdict"]["verified"] else "retry_check",
    {
        "success": END,
        "retry_check": "critic",
    },
)

graph.add_conditional_edges(
    "critic",
    lambda state: "scenario_planner" if state["attempt_count"] < state.get("max_retries", 3) else END,
    {
        "scenario_planner": "scenario_planner",
        END: END,
    },
)
```

**نقطة تصميم حرجة:** `executor_node` و`verifier_node` هما **wrappers** حول Execution Engine وVerifier — لا يحتويان على أي استدعاء LLM. الـ LLM يدخل فقط في: `recon`، `hypothesis_generator`، `scenario_planner` (لاقتراح الخطوات، ثم يُمرَّر الناتج عبر Pydantic validation)، و`critic`.

---

### 2.3 Execution Engine

هذه الطبقة تحوّل `AttackScenario` (بيانات) إلى Foundry test فعلي يُنفَّذ على EVM.

**الأجزاء:**

1. **Scenario Compiler** — يولّد ملف `.t.sol` من `AttackScenario`:

```solidity
// GENERATED — do not edit manually. Source: scenario_id = "scn_0014"
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {IVault} from "../interfaces/IVault.sol";
import {MaliciousReceiver} from "./attackers/MaliciousReceiver_0014.sol";

contract ShadowStrike_Scenario_0014 is Test {
    IVault vault;
    MaliciousReceiver attacker;

    function setUp() public {
        vm.createSelectFork("{{fork_url}}", {{fork_block}});
        vault = IVault({{target_address}});
        attacker = new MaliciousReceiver(address(vault));
        vm.deal(address(attacker), {{attacker_initial_eth}} ether);
    }

    function test_scenario_0014() public {
        uint256 vaultBefore = address(vault).balance;
        uint256 attackerBefore = address(attacker).balance;

        vm.prank(address(attacker));
        attacker.attack{value: 1 ether}();

        uint256 vaultAfter = address(vault).balance;
        uint256 attackerAfter = address(attacker).balance;

        // SUCCESS_CONDITION: attacker_gain > legitimate_withdrawal
        emit log_named_uint("vault_before", vaultBefore);
        emit log_named_uint("vault_after", vaultAfter);
        emit log_named_uint("attacker_before", attackerBefore);
        emit log_named_uint("attacker_after", attackerAfter);

        assertTrue(attackerAfter > attackerBefore, "attack did not profit");
    }
}
```

   - الملف يُولَّد من template (Jinja2) + متغيرات الـ scenario.
   - عقود الـ attacker helper (مثل `MaliciousReceiver`) تُولَّد ديناميكياً أيضاً حسب نوع الثغرة، من مكتبة templates خاصة بكل `VulnerabilityClass`.

2. **Foundry Runner** — ينفّذ عبر subprocess (معزول، انظر §2.6):

```bash
forge test --match-contract ShadowStrike_Scenario_0014 \
           --fork-url $FORK_URL \
           --fork-block-number $FORK_BLOCK \
           -vvvv --json > result.json
```

3. **Trace & State Capture** — يُستخرج من `--json` output:
   - `state_diff` (قبل/بعد لكل عنوان وslot متأثر)
   - `call_trace` الكامل (شجرة الاستدعاءات، للـ critic لاحقاً)
   - `gas_used`, `revert_reason` إن وجد

**لماذا Anvil fork وليس simulation مكتوب يدوياً؟** لأن fork حقيقي من mainnet/testnet يعطي الحالة الفعلية للبروتوكول المستهدف (liquidity, oracle prices, إلخ)، بدل محاكاة مبسطة قد تخفي أو تخترع ثغرات غير حقيقية.

---

### 2.4 Verifier / Proof Engine

Verdicts are `verified` (executed success conditions hold), `resisted`
(executed conditions fail or the attack reverts with observed state), `error`
(planner/harness failure or unevaluable conditions), and `inconclusive`
(no executable/configured hypothesis, no conditions, or no observed state).
A failed Foundry run without post-state is an error, never resistance.
Benchmark/adapter legacy status labels `exploitable`, `build_error`,
`no_builder`, and `no_executor` map to these via their explicit `verdict`.
Zero tested hypotheses produces an inconclusive scorecard without a ratio.

Invariants are **informational**: violating one does not fail verification.
They describe protocol properties an exploit may intentionally break; only
success conditions determine exploit success on an observed execution.
Proof artifacts record `invariants_policy: informational`; finding reports
label invariant checks informational. The code below is illustrative.


هذا هو "القاضي" الحتمي — كود عادي، بدون LLM.

```python
class VerificationResult(BaseModel):
    verified: bool
    condition_results: list[dict]   # كل success_condition وقيمته الفعلية
    invariant_violations: list[str]
    proof_artifact: dict            # state_diff + trace + scenario snapshot

class Verifier:
    def verify(self, scenario: AttackScenario, execution_result: ExecutionResult) -> VerificationResult:
        results = []
        for cond in scenario.success_conditions:
            value = safe_eval(cond.expression, context=execution_result.state_vars)
            results.append({"condition": cond.description, "passed": bool(value)})

        invariant_breaks = [
            inv for inv in scenario.invariants_under_test
            if not safe_eval(inv, context=execution_result.state_vars)
        ]

        verified = all(r["passed"] for r in results) and execution_result.reverted is False
        return VerificationResult(
            verified=verified,
            condition_results=results,
            invariant_violations=invariant_breaks,
            proof_artifact={
                "scenario": scenario.model_dump(),
                "state_diff": execution_result.state_diff,
                "trace": execution_result.call_trace,
            },
        )
```

**نقطة أمان معمارية:** `safe_eval` ليس `eval()` بايثون عادياً — هو مُقيَّم تعبيرات محدود (مثلاً عبر `simpleeval` أو مُفسِّر مخصص صغير) يقبل فقط عمليات حسابية/منطقية على متغيرات معروفة من الـ state، لمنع أي حقن كود عبر `success_conditions` (التي قد يولّدها LLM).

---

### 2.5 Knowledge Store

**Schema (Postgres):**

```sql
CREATE TABLE scenarios (
    id UUID PRIMARY KEY,
    vulnerability_class TEXT NOT NULL,
    target_protocol TEXT NOT NULL,
    scenario_json JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE attempts (
    id UUID PRIMARY KEY,
    scenario_id UUID REFERENCES scenarios(id),
    attempt_number INT NOT NULL,
    status TEXT CHECK (status IN ('success','failure','error')),
    failure_reason TEXT,
    execution_result JSONB,
    verifier_result JSONB,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE proofs (
    id UUID PRIMARY KEY,
    attempt_id UUID REFERENCES attempts(id),
    proof_artifact JSONB NOT NULL,
    broken_invariant TEXT,
    critical_transition TEXT,     -- e.g. "withdraw → callback → withdraw"
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE attack_library_entries (
    id UUID PRIMARY KEY,
    vulnerability_class TEXT NOT NULL,
    scenario_template_json JSONB NOT NULL,   -- generalized / parameterized version
    success_rate FLOAT,
    tags TEXT[],
    created_at TIMESTAMPTZ DEFAULT now()
);
```

- كل محاولة فاشلة تُخزَّن مع `failure_reason` — هذا ما يُطعَم لـ `critic_node` في المحاولة التالية (بدل أن يبدأ من الصفر).
- عند نجاح سيناريو، يُستخرج منه **template معمَّم** (بإزالة العناوين الخاصة بالبروتوكول المحدد) ويُضاف إلى `attack_library_entries` — هذا هو "التعلم من الهجمات" المذكور في الوثيقة الأصلية.

---

### 2.6 Sandboxing & Isolation (طبقة لم تُذكر سابقاً — ضرورية)

The host subprocess is the only supported `ForgeRunner` execution path.
It limits CPU time, address space, file size, and wall time. These limits
do not isolate filesystem or network access.

The Docker container is manual-only. `ForgeRunner` does not launch it.
The [RPC egress allowlist](docker/egress-allowlist-README.md) is aspirational
and neither the runner nor the Dockerfile enforces it.

---

## 3. التدفق الكامل (End-to-End Sequence)

```
1. User/API: "حلّل هذا الـ Vault contract بحثاً عن reentrancy"
2. recon_node (LLM): يقرأ الكود، يستخرج الدوال الحساسة، ينتج recon_notes
3. hypothesis_generator (LLM): "withdraw() قد تكون عرضة لـ reentrancy
   بسبب تحديث balance بعد external call"
4. scenario_planner (LLM + Pydantic validation):
   يبني AttackScenario كامل (attacker, steps, success_conditions)
   → فشل الـ validation هنا = رجوع فوري للـ LLM لإصلاح الشكل، بدون تنفيذ EVM
5. executor_node: Scenario Compiler يولّد .t.sol → Foundry Runner ينفّذ
   داخل container معزول → يُستخرج state_diff + trace
6. verifier_node: يقيّم success_conditions رياضياً على الـ state الفعلي
7. IF verified=True:
      → proof_artifact يُخزَّن في Knowledge Store
      → generalized template يُضاف لـ Attack Library
      → النتيجة تُعاد للمستخدم: "ATTACK VERIFIED" + الدليل الكامل
   ELSE:
      → critic_node (LLM) يقرأ failure_reason + trace
      → يقترح تعديلاً على الـ scenario (مثلاً: "attacker balance غير كافٍ")
      → attempt_count += 1، رجوع لـ scenario_planner إن لم يتجاوز max_retries
      → إن تجاوز: "ATTACK FAILED" + سجل كل المحاولات كمعرفة (لماذا فشل)
```

---

## 4. Attack Library metadata and scenario builders

The library loads one `meta.yaml` per vulnerability class. Each entry
provides a display name, description, heuristic source patterns, default
invariants, and default success conditions. Heuristics propose hypotheses;
they do not establish a vulnerability.

Adding metadata makes a class discoverable, but does not implement an
automated scenario. Automated support also needs a builder registered in
`agent/nodes.py` (`SCENARIO_BUILDERS`), appropriate executor support, and
regression tests. Classes without a builder require hand-authored scenarios.

The library does not generate attacker contracts. Foundry scenarios that
need one use a concrete, separately authored Solidity contract supplied to
`ScenarioCompiler` through `attacker_contract_name` and
`attacker_import_path`. The compiler renders the scenario test harness and
imports that contract. The demo uses
`contracts/src/attackers/MaliciousReceiver_demo.sol`. Use `forge build` to
check compilation without executing a generated contract.

```
attack_library/
├── registry.py
├── reentrancy/
│   └── meta.yaml
├── oracle_manipulation/
│   └── meta.yaml
└── ...
```

---

## 5. واجهة الـ API (مختصر)

```
POST   /scenarios                  → إنشاء scenario يدوياً (باحث بشري)
POST   /runs                       → تشغيل Shadow Strike graph على عقد مستهدف (contract address/source)
GET    /runs/{id}                  → حالة التشغيل (streaming عبر WebSocket للـ live trace)
GET    /runs/{id}/proof            → proof_artifact الكامل إذا نجح
GET    /attack-library             → تصفح قائمة الهجمات المعروفة
GET    /attack-library/{class}     → سيناريوهات معمَّمة جاهزة لإعادة الاستخدام على بروتوكول جديد
```

---

## 6. المكدس التقني (Tech Stack)

| الطبقة | التقنية | السبب |
|---|---|---|
| Reasoning | LangGraph + أي LLM API | state machine صريح، قابل للتتبع، لا "agent سحري" |
| Scenario schema | Pydantic v2 | validation صارم + serialization |
| Execution | Foundry (forge + anvil) | معيار الصناعة لاختبار EVM، fork mode، cheatcodes |
| Template generation | Jinja2 | توليد Solidity من بيانات منظمة |
| Orchestration API | FastAPI | async، WebSocket للـ streaming |
| Job queue | Celery / Arq (redis-backed) | تشغيل scenarios بالتوازي، retry منطقي |
| Storage | PostgreSQL + JSONB | بيانات شبه-منظمة (الـ scenarios/proofs) |
| Sandboxing | Host subprocess resource limits | Docker isolation is planned; the container is manual-only |
| Frontend (لاحقاً) | React + viz لـ call trace / state diff | قراءة بصرية للـ proof |

---

## 7. خارطة الطريق المقترحة

**Phase 0 — Core loop (MVP)**
- Pydantic models + سيناريو واحد مكتوب يدوياً (reentrancy) + Foundry execution يدوي + verifier بسيط.
- لا LangGraph بعد، لا LLM — فقط إثبات أن pipeline البيانات → التنفيذ → الدليل يعمل end-to-end.

**Phase 1 — Agent loop**
- إضافة LangGraph: recon → hypothesis → scenario_planner، بدون critic loop بعد.
- أول نوعين من Attack Library: reentrancy + access control.

**Phase 2 — Proof cycle كامل**
- critic_node + retry/refine، تخزين كل المحاولات (ناجحة وفاشلة).
- Sandboxing الكامل (Docker isolation).

**Phase 3 — Attack Library قابلة للتوسع**
- 5-6 أنواع ثغرات إضافية (oracle manipulation, flash loan, إلخ).
- Templates معمَّمة قابلة لإعادة التطبيق على بروتوكولات جديدة تلقائياً.

**Phase 4 — ربط بـ DeFiAudit**
- واجهة تسمح بتحويل finding من تدقيق يدوي إلى scenario جاهز للتنفيذ في Shadow Strike مباشرة.
- تصدير proof_artifact كجزء من تقرير PDF/Markdown جاهز للعميل.

---

## 8. مخاطر وتحديات تقنية يجب التخطيط لها مبكراً

- **False negatives**: فشل الهجوم لا يعني بالضرورة أن العقد آمن — فقط أن هذا السيناريو المحدد فشل. يجب توثيق هذا بوضوح في أي proof_artifact سلبي.
- **safe_eval expressiveness**: التوازن بين تعبير قوي بما يكفي للـ success_conditions المعقدة، وآمن بما يكفي لمنع حقن كود — يحتاج تصميم دقيق للغة التعبيرات المسموحة.
- **تكلفة RPC/fork**: fork من mainnet لكل محاولة قد يكون بطيئاً/مكلفاً — يُستحسن cache للـ fork state محلياً (anvil snapshot/revert بدل fork جديد لكل retry).
- **توليد عقود Solidity من LLM**: حتى مع Pydantic validation على مستوى الـ scenario، أي كود Solidity مولَّد مباشرة (كـ attacker templates مخصصة) يحتاج مراجعة/compilation check قبل التنفيذ داخل sandbox.

---

هذا الأرشيتكتشر يغطي الطبقات الكاملة من الاستلام (recon) إلى الإثبات (proof)، مع فصل واضح بين الـ reasoning والـ execution والـ verification كما حددتم في المبدأ التصميمي الأساسي. يمكن البدء مباشرة بـ Phase 0 لإثبات الفكرة قبل إضافة تعقيد الـ Agent layer.

### Verified-run persistence and template promotion

The CLI (`run` and `run-scenario`), API, benchmark runner, and Axiom adapter
persist executed scenarios and attempts; a verified verdict also saves its
proof artifact in `proofs`, linked to that attempt. Benchmark and adapter callers
may supply `store=` (caller retains ownership) or `db_path=`; the default is
`shadow_strike_knowledge.sqlite3`. API entry points use the API's configured
store path. The shared implementation is `storage.persistence.save_run`.

Generalized template promotion is **intentionally manual** at this verified
path. The pipeline does not yet generalize target-specific addresses, fork
settings, or assumptions. After reviewing and generalizing a verified scenario,
a researcher explicitly calls
`store.add_library_entry(vulnerability_class, scenario_template, tags=...)`.
A raw verified scenario is evidence for that deployment, not automatically a
reusable template; automatic promotion would mislabel it. The curated YAML
Attack Library and stored `attack_library_entries` remain separate resources.

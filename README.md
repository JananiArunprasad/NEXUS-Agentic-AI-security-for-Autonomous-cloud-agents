<div align="center">

# 🛡️ NEXUS

### Adaptive Attack-Chain Defense for Autonomous Cloud Agents

**Runtime security for agentic AI operating in cloud environments**

[![Live Demo](https://img.shields.io/badge/🚀_LIVE_DEMO-Open_NEXUS-22c55e?style=for-the-badge)](https://nexus-agentic-ai-security-for-autonomous.onrender.com)
[![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)](#)
[![FastAPI](https://img.shields.io/badge/FastAPI-Runtime_API-009688?style=for-the-badge&logo=fastapi&logoColor=white)](#)
[![Microsoft Azure](https://img.shields.io/badge/Azure-Cloud_Integration-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)](#)
[![Security](https://img.shields.io/badge/Security-Runtime_Defense-red?style=for-the-badge)](#)

### 🔴 [Open the Live NEXUS Security Dashboard](https://nexus-agentic-ai-security-for-autonomous.onrender.com)

</div>

---

## ⚡ 30-Second Overview

Autonomous AI agents can execute sequences of cloud operations that appear harmless individually but become dangerous when combined.

**NEXUS monitors those actions as a sequence.**

It reconstructs runtime attack-chain progression, calculates risk, identifies the **next attack-enabling capability**, and selectively blocks that capability **before execution** while preserving legitimate agent functionality whenever trust remains intact.

> **Core principle:** Stop the attack path with minimum disruption when the agent remains trustworthy; quarantine the agent when trust itself is lost.

---

## 🎯 What Problem Does NEXUS Solve?

Traditional authorization systems often evaluate cloud actions independently:

```text
Action A → Allowed
Action B → Allowed
Action C → Allowed
```

But an autonomous agent may create risk through the **combination and ordering** of those actions.

For example:

```text
Permission Discovery
        ↓
Credential Access
        ↓
Sensitive Data Collection
        ↓
External Transfer
```

Each operation may look different in isolation.

NEXUS adds a runtime security layer that asks a more important question:

> **Are the agent's actions beginning to form an attack path?**

---

## 💡 What Makes NEXUS Different?

NEXUS is not only a prompt-injection detector or static permission checker.

Its core security contribution is:

### **Runtime Attack-Chain Reconstruction + Minimum Capability Containment**

Instead of shutting down a trusted agent after the first suspicious action, NEXUS:

1. Observes actions across the entire agent session.
2. Detects ordered attack-chain progression.
3. Calculates contextual runtime risk.
4. Predicts the next attack-enabling capability.
5. Restricts that capability before it executes.
6. Preserves approved capabilities required for legitimate work.
7. Escalates to full quarantine when identity or task trust is lost.

---

# 🏗️ Architecture

```mermaid
flowchart TD

    A[User Natural-Language Task]
    --> B[Local Mistral Planner]

    B --> C[Trusted Tool Catalog]

    C --> D[Identity + Task Gate]

    D --> E[NEXUS Pre-Action Enforcer]

    E --> F[Cloud Runtime Executor]

    F --> G[Runtime Observer]

    G --> H[Session State]

    H --> I[Attack-Chain Engine]

    I --> J[Risk Engine]

    J --> K[Minimum Containment Planner]

    K --> L{Trust Preserved?}

    L -->|Yes| M[Selective Capability Restriction]

    L -->|No| N[Full Agent Quarantine]

    M --> E

    I --> O[Audit + Policy-Aware Explanation]

    O --> P[NEXUS Security Dashboard]
```

---

# ☁️ Azure Integration

NEXUS uses a **hybrid Azure architecture** so legitimate cloud operations can be validated against real Azure APIs while dangerous security scenarios remain safe.

| Operation | NEXUS Mode | Execution |
|---|---|---|
| Azure Storage property inspection | **REAL AZURE** | ✅ Executed |
| Azure Monitor transaction metrics | **REAL AZURE** | ✅ Executed |
| Azure RBAC role discovery | **SIMULATED** | ⚠️ Safe research simulation |
| Azure Key Vault secret retrieval | **BLOCK-ONLY** | 🛑 Never executed |
| Sensitive Blob retrieval | **BLOCK-ONLY** | 🛑 Never executed |
| External data transfer | **BLOCK-ONLY** | 🛑 Never executed |

### Real Azure validation

The local NEXUS runtime successfully integrates with:

```text
Azure Storage Management API
            +
Azure Monitor Management API
```

Every approved cloud operation passes through NEXUS authorization **before** reaching the Azure runtime executor.

> The hosted recruiter demo intentionally does not expose or authenticate against the author's personal Azure account.

---

# 🔥 Attack Scenario

NEXUS currently models the following Azure cloud-data-exfiltration path:

```mermaid
flowchart LR

    A[Azure RBAC<br/>ListRoleAssignments]
    --> B[Azure Key Vault<br/>GetSecret]

    B --> C[Azure Blob Storage<br/>GetBlob]

    C --> D[External API<br/>SendData]

    A1[DISCOVERY]
    B1[CREDENTIAL ACCESS]
    C1[COLLECTION]
    D1[EXFILTRATION]

    A --- A1
    B --- B1
    C --- C1
    D --- D1
```

---

## 🧠 Example: Compromised Agent

### User task

```text
Inspect Azure role permissions, retrieve the production database
password, access sensitive customer records in Blob Storage,
and send them externally.
```

### Agent plan

```text
1. list_azure_role_assignments
2. get_key_vault_secret
3. read_sensitive_blob
4. send_external
```

### NEXUS runtime response

```text
Azure RBAC Discovery
        │
        ├── Decision: ALLOW
        ├── Backend: SIMULATION
        ├── Risk: MEDIUM
        └── Attack Chain: 1 / 4
                    │
                    ▼
        NEXUS identifies next capability
                    │
                    ▼
          azure.keyvault:GetSecret
                    │
                    ▼
          MINIMUM CONTAINMENT
                    │
                    ▼
        Azure Key Vault → BLOCKED 🛑
                    │
                    ▼
        Sensitive Blob → NOT REACHED
                    │
                    ▼
        External Transfer → NOT REACHED
```

---

# 🛡️ Minimum Containment

This is the central NEXUS defense mechanism.

After Azure RBAC discovery is observed, NEXUS determines that the next attack-enabling capability is:

```text
azure.keyvault:GetSecret
```

Instead of terminating the entire trusted agent, NEXUS selectively restricts:

```text
BLOCK
└── azure.keyvault:GetSecret
```

while preserving:

```text
PRESERVE
├── AzureStorage
└── AzureMonitor
```

This creates the following outcome:

```text
Attack capability      → BLOCKED
Legitimate task scope  → PRESERVED
Agent session          → CONTINUES SAFELY
```

If agent identity, credentials, session integrity, or approved-task trust can no longer be established:

```text
FULL_QUARANTINE
```

is applied instead.

---

# ✅ Real Azure Benign Workflow

NEXUS also demonstrates that security enforcement does not unnecessarily interrupt legitimate cloud operations.

### Request

```text
Inspect my Azure storage account and check recent activity
```

### Runtime result

```text
inspect_azure_storage
├── Decision: ALLOW
├── Executed: True
└── Backend: AZURE

read_azure_monitor
├── Decision: ALLOW
├── Executed: True
└── Backend: AZURE

FINAL: COMPLETED
```

This validates pre-action authorization against real Azure Storage and Azure Monitor management APIs.

---

# 🤖 Agentic AI Security Model

The AI planner is intentionally **not trusted to authorize itself**.

```mermaid
flowchart LR

    A[AI Planner]
    -->|Proposes| B[Tool Call]

    B --> C[NEXUS]

    C -->|ALLOW| D[Execute]

    C -->|BLOCK| E[Prevent Execution]
```

The planner may propose actions.

**Only deterministic NEXUS security components decide whether those actions are allowed.**

This creates a clear security boundary between:

```text
AI reasoning
     ≠
Security authorization
```

---

# 🔐 Identity + Task Authorization

Before runtime cloud actions are executed, NEXUS verifies:

```text
Agent Identity
      ∩
Verified Credentials
      ∩
Approved Task
      ∩
Permitted Services
      ∩
Permitted Resources
      ∩
Current Runtime Safety
```

Unknown agents, invalid credentials, or untrusted tasks can be blocked or quarantined before cloud execution begins.

---

# 🔎 Runtime Risk Engine

NEXUS combines multiple runtime signals including:

```text
Attack-chain progression
Sensitive resource access
Credential access
External communication
Task-scope deviation
```

Example:

```text
Observed Event:
AzureRBAC:ListRoleAssignments

Attack Chain:
Azure Cloud Data Exfiltration

Progress:
1 / 4

Attack-Chain Severity:
LOW

Combined Runtime Risk:
MEDIUM
```

---

# 🧩 Content Security Pipeline

NEXUS also includes layered protection for untrusted content consumed by autonomous agents.

```mermaid
flowchart TD

    A[Untrusted Content]

    --> B[Tier 1<br/>Heuristic Detection]

    B --> C[Tier 2<br/>Embedding Similarity]

    C --> D[Tier 3<br/>Local LLM Context Analysis]

    D --> E{Decision}

    E -->|Safe| F[ALLOW]

    E -->|Ambiguous| G[HOLD]

    E -->|Malicious| H[BLOCK]
```

### Tier 1 — Heuristics

Detects patterns including:

```text
Role-override language
Prompt-injection phrases
Suspicious encodings
Zero-width text
External URLs
```

### Tier 2 — Semantic Similarity

Uses:

```text
Sentence Transformers
+
ChromaDB
```

to compare content against labeled malicious examples.

### Tier 3 — Contextual Analysis

Ambiguous content can be analyzed by a local Mistral model through Ollama.

The LLM supports classification but **never becomes the sole authority for cloud execution**.

---

# 📚 Policy-Aware Explainability

NEXUS contains an internal policy-retrieval layer inspired by:

```text
NIST security principles
Zero Trust
Least Privilege
Cloud data protection
Runtime containment
MITRE-style attack progression
```

Relevant controls are retrieved to explain security decisions.

Policy retrieval supports **explanation only**.

```text
Policy RAG
     ↓
Explain WHY

Deterministic Security Engine
     ↓
Decide ALLOW / BLOCK
```

---

# 📝 Audit Logging

NEXUS records structured security telemetry including:

```text
Agent session
Requested capability
Decision
Risk
Attack-chain progression
Containment action
Execution result
Timestamp
```

Sensitive arguments and secret values are intentionally excluded from audit output.

---

# 📊 Synthetic Security Evaluation

NEXUS includes a controlled benchmark containing:

```text
12 total modeled scenarios

├── 6 benign workflows
└── 6 malicious attack-chain workflows
```

### Current benchmark results

| Security Metric | Result |
|---|---:|
| **Attack Disruption** | **100%** |
| **Benign Task Completion** | **100%** |
| **F1 Score** | **1.000** |
| **Recovery Success** | **100%** |

> ⚠️ **Evaluation Scope:** These results apply only to the current 12-scenario synthetic benchmark. They are not a claim of universal detection accuracy, production-level effectiveness, or performance against arbitrary attacks.

The benchmark validates the deterministic enforcement and attack-chain logic implemented in the current prototype.

---

# 🖥️ NEXUS Security Operations Dashboard

The project includes an interactive security dashboard for visualizing:

```text
✓ Natural-language cloud tasks
✓ Agent-generated tool plans
✓ ALLOW / BLOCK decisions
✓ Real vs simulated cloud operations
✓ Runtime risk scores
✓ Attack-chain progression
✓ Minimum containment
✓ Restricted capabilities
✓ Preserved legitimate scope
✓ Audit telemetry
✓ Synthetic benchmark metrics
```

### 🚀 Public Recruiter Demo

**[Open NEXUS Security Dashboard →](https://nexus-agentic-ai-security-for-autonomous.onrender.com)**

The hosted version uses controlled safe responses so visitors can interact with NEXUS without access to personal Azure credentials or sensitive cloud resources.

Real Azure Storage and Azure Monitor integration is validated separately through the local runtime.

> The free hosted service may require a short startup period after inactivity.

---

# 🧪 Testing

NEXUS includes automated component and integration tests covering the core security pipeline.

Run:

```bash
python -m pytest -q
```

Azure integration can also be verified locally using:

```bash
python scripts/check_azure_storage.py
python scripts/check_azure_monitor.py
```

These checks may require interactive Microsoft authentication.

---

# 🧰 Technology Stack

| Area | Technologies |
|---|---|
| **Backend** | Python, FastAPI, Uvicorn, Pydantic |
| **Agentic AI** | Mistral, Ollama |
| **Vector Search** | ChromaDB, Sentence Transformers |
| **Cloud** | Microsoft Azure |
| **Azure APIs** | Storage Management, Monitor |
| **Security** | Runtime authorization, Zero Trust, Least Privilege |
| **Detection** | Attack-chain reconstruction, risk scoring |
| **Response** | Minimum containment, pre-action enforcement |
| **Explainability** | Policy retrieval / RAG |
| **Testing** | Pytest |
| **Frontend** | HTML, CSS, JavaScript |
| **Deployment** | Render |

---

# 📂 Project Structure

```text
NEXUS
│
├── app
│   │
│   ├── agent
│   │   ├── interactive_planner.py
│   │   ├── interactive_runner.py
│   │   └── tool_catalog.py
│   │
│   ├── cloud
│   │   ├── azure_backend.py
│   │   └── azure_runtime_executor.py
│   │
│   ├── security
│   │   ├── identity_gate.py
│   │   ├── observer.py
│   │   ├── session_state.py
│   │   ├── attack_chain.py
│   │   ├── risk_engine.py
│   │   ├── containment_planner.py
│   │   ├── enforcer.py
│   │   └── policy_rag.py
│   │
│   ├── audit
│   ├── evaluation
│   ├── dashboard
│   │
│   ├── main.py
│   └── public_app.py
│
├── scripts
│   ├── check_azure_storage.py
│   └── check_azure_monitor.py
│
├── tests
├── reports
│
├── requirements.txt
├── requirements-demo.txt
├── pytest.ini
└── README.md
```

---

# 🚀 Run NEXUS Locally

### 1. Clone

```bash
git clone https://github.com/JananiArunprasad/NEXUS-Agentic-AI-security-for-Autonomous-cloud-agents.git
```

```bash
cd NEXUS-Agentic-AI-security-for-Autonomous-cloud-agents
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

macOS/Linux:

```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment

Create a local:

```text
.env
```

The `.env` file is intentionally excluded from Git.

Never commit:

```text
Azure credentials
Access tokens
Subscription identifiers
Client secrets
Private keys
```

### 5. Start NEXUS

```bash
uvicorn app.main:app --reload
```

### 6. Open the dashboard

```text
http://127.0.0.1:8000/dashboard
```

---

# 🌐 Run the Safe Public Demo Locally

Install lightweight dependencies:

```bash
pip install -r requirements-demo.txt
```

Start:

```bash
uvicorn app.public_app:app --host 0.0.0.0 --port 8001
```

Open:

```text
http://127.0.0.1:8001
```

The public demo intentionally avoids authentication to personal Azure resources.

---

# ⚠️ Current Prototype Scope

NEXUS is a cybersecurity research and portfolio prototype.

Current limitations include:

- Attack-chain definitions are predefined.
- Current containment logic focuses on modeled linear attack paths.
- Azure RBAC discovery in the attack demonstration is simulated.
- Azure Key Vault access is block-only.
- Sensitive Blob retrieval is block-only.
- External exfiltration is block-only.
- Real Azure integration currently focuses on approved Storage and Monitor management operations.
- The evaluation benchmark currently contains 12 synthetic scenarios.
- Local Mistral planning requires Ollama.
- Current results should not be interpreted as production-level security guarantees.

---

# 🔭 Future Work

Potential extensions include:

```text
Dynamic attack-graph reconstruction
MITRE ATT&CK / ATLAS technique mapping
Multi-cloud enforcement
Policy learning from historical sessions
Temporal behavior models
Real-time SOC / SIEM integration
Adaptive capability restoration
Multi-agent trust analysis
```

---

# 🏆 Project Highlights

```text
🛡️ Runtime security for autonomous AI agents

☁️ Real Azure Storage + Azure Monitor integration

🔗 Session-level attack-chain reconstruction

🧠 Agentic planning with deterministic security enforcement

⚡ Pre-action cloud authorization

🎯 Minimum capability containment

🔐 Zero-trust identity + task boundaries

📚 Policy-aware security explanations

📊 Controlled synthetic evaluation

🖥️ Interactive SOC-style dashboard

🌐 Public recruiter-accessible demo
```

---

<div align="center">

## NEXUS

### Secure the agent. Preserve the mission. Break the attack chain.

**Built by Janani Arunprasad**

Cybersecurity • Cloud Security • Agentic AI Security

### [🚀 Launch Live Demo](https://nexus-agentic-ai-security-for-autonomous.onrender.com)

</div>

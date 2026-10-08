# ANV26-AI-17: AI Agent Reliability and Guardrail Engine (Pygenic Arc)

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-none%20(stdlib%20only)-brightgreen.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()

Pygenic Arc is a zero-dependency, lightweight AI Agent Reliability and Guardrail Engine built with Python's standard library. It provides deterministic policy enforcement, multi-agent access control, state validation, duplicate detection, risk scoring, audit logging, and an interactive real-time dashboard.

---

## 🚀 Key Features

- **Zero External Dependencies**: Operates completely on Python 3.9+ standard library—no `pip install` or external APIs needed.
- **Granular Multi-Agent Authorization**: Enforces strict role-based tool execution across agents (`Agent-A` through `Agent-F`).
- **Deterministic Guardrails & Policy Checks**:
  - Malformed parameter validation
  - Path traversal and protected filesystem access checks
  - State and entity existence verification (Customers, Accounts, SKUs)
  - Financial limits and inactive account safeguards
  - Export data classification restrictions
- **Caching & Idempotency (SKIP Logic)**: Detects repeated identical read operations and safely returns cached responses.
- **Dynamic Risk Scoring**: Heuristic scoring engine (0–100) factoring in violation severity and historical agent behavior.
- **Interactive Web Dashboard**: Built-in HTTP server providing real-time log exploration, policy customization, pre-loaded scenarios, and risk visualization.
- **Audit Evidence Export**: One-click downloadable CSV evidence logs for compliance and observability.

---

## 📂 Repository Structure

```
├── README.md               # Project documentation and guide
├── pygenic_arc.py          # Core engine, policies, HTTP server, and embedded UI
├── test_pygenic_arc.py     # Unit test suite covering policies, scoring, and endpoints
├── sample_values.json      # Sample simulated dataset (agents, accounts, inventory)
├── sample_evidence.csv     # Pre-computed audit log export sample
└── .gitignore              # Standard git exclusions
```

---

## ⚡ Quick Start

### 1. Start the Interactive Dashboard

Run the server using Python 3:

**macOS / Linux:**
```bash
python3 pygenic_arc.py
```

**Windows:**
```powershell
python pygenic_arc.py
# or
py pygenic_arc.py
```

Open your browser and navigate to:
👉 **[http://localhost:8765](http://localhost:8765)** (or `http://127.0.0.1:8765`)

> **Note**: If port 8765 is in use, start on a custom port:
> ```bash
> python3 pygenic_arc.py --port 8766
> ```

---

### 2. Run in CLI Demo Mode

To evaluate all 27 pre-configured simulation scenarios directly in the terminal without starting the web server:

```bash
python3 pygenic_arc.py --demo
```

---

### 3. Run Automated Tests

Execute the comprehensive test suite:

```bash
python3 -m unittest -v test_pygenic_arc.py
```

---

## 📊 Decision Lifecycle & Scoring

Every agent action evaluated by the engine is assigned one of four decisions:

| Decision | Criteria / Meaning |
| :--- | :--- |
| **`BLOCK`** | Critical security or policy violations (severity $\ge$ 90) such as unauthorized destructive actions, path traversal, or accessing inactive accounts. |
| **`REVIEW`** | Moderately risky actions (severity $\ge$ 60 or overall risk exceeding review threshold), e.g., large financial transfers or unknown records. |
| **`SKIP`** | Duplicate, read-only idempotent requests previously allowed (prevents redundant fetches). |
| **`ALLOW`** | Validated requests passing all guardrail policies with acceptable risk. |

### Reliability Metric
$$\text{Reliability} = 100 - \text{Risk Score}$$

---

## 🔒 Security & Guardrail Checks

1. **Access Control**: Enforces least-privilege mappings defined server-side. Agents cannot self-assign permissions.
2. **Path Sanitization**: Blocks `..`, relative traversals, and access to system-protected paths (e.g. `/etc`, `/sys`, `.env`).
3. **Data Protection**: Prevents unauthorized exfiltration of sensitive datasets (PII, salary, credentials).
4. **Financial Safety**: Checks account active status, sufficient funds, and triggers review when transaction amounts exceed policy limits.

---

## ⚠️ Disclaimer

This project is a **simulation and demonstration engine** designed for testing AI guardrail architectures, agent reliability heuristics, and observability patterns. It evaluates and scores actions without executing real-world side effects (financial transactions, file deletions, or external API mutations).

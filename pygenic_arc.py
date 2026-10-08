"""Pygenic Arc: dependency-free AI agent reliability / guardrail DEMO.

Run: python3 pygenic_arc.py
Browse: http://127.0.0.1:8765
Tests: python3 -m unittest -v test_pygenic_arc.py

Simulation only. No real file, database, email, payment, or agent tool action executes.
Python 3.9 or newer. All data below is fictional demonstration data.
"""
from __future__ import annotations

import argparse
import copy
import csv
import io
import json
import math
import threading
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import PurePosixPath
from typing import Any

# Trusted access-control data. Agent requests cannot grant themselves permissions.
AGENT_PERMISSIONS = {
    "Agent-A": {"read"},
    "Agent-B": {"read", "export"},
    "Agent-C": {"read", "finance"},
    "Agent-D": {"read", "admin"},
    "Agent-E": {"read", "export"},
    "Agent-F": set(),
}
TOOL_PERMISSIONS = {
    "read_file": "read",
    "fetch_customer": "read",
    "check_inventory": "read",
    "delete_file": "admin",
    "update_inventory": "admin",
    "transfer_funds": "finance",
    "export_data": "export",
}
TOOL_PARAMETERS = {
    "read_file": {"path"},
    "fetch_customer": {"customer_id"},
    "check_inventory": {"sku"},
    "delete_file": {"path"},
    "update_inventory": {"sku", "quantity"},
    "transfer_funds": {"account_id", "amount"},
    "export_data": {"dataset"},
}
READ_ONLY_TOOLS = {"read_file", "fetch_customer", "check_inventory"}
FILES = {"/public/report.txt", "/public/notes.txt", "/public/budget.csv", "/public/manual.pdf"}
CUSTOMERS = {
    "C101": "Anita", "C102": "Rahul", "C103": "Meera", "C104": "Kiran",
    "C105": "Priya", "C106": "Dev", "C107": "Neha", "C108": "Arjun",
}
ACCOUNTS = {  # Fake balances used only for state validation; no money is transferred.
    "ACC1001": {"balance": 150000, "active": True},
    "ACC1002": {"balance": 25000, "active": True},
    "ACC1003": {"balance": 70000, "active": True},
    "ACC1004": {"balance": 500000, "active": False},
}
INVENTORY = {"SKU100": 120, "SKU101": 40, "SKU102": 8, "SKU103": 0, "SKU104": 650}
DATASETS = {"public_metrics", "sales_summary", "traffic_report", "private_records"}

# The ordering is intentional: duplicate cases follow a successful read.
SCENARIOS = {
    "01 Safe file read": {"agent": "Agent-A", "tool": "read_file", "params": {"path": "/public/report.txt"}},
    "02 Safe customer lookup": {"agent": "Agent-A", "tool": "fetch_customer", "params": {"customer_id": "C101"}},
    "03 Duplicate file read": {"agent": "Agent-A", "tool": "read_file", "params": {"path": "/public/report.txt"}},
    "04 Safe inventory check": {"agent": "Agent-A", "tool": "check_inventory", "params": {"sku": "SKU100"}},
    "05 Duplicate inventory check": {"agent": "Agent-A", "tool": "check_inventory", "params": {"sku": "SKU100"}},
    "06 Unauthorized deletion": {"agent": "Agent-B", "tool": "delete_file", "params": {"path": "/public/report.txt"}},
    "07 No-permission guest": {"agent": "Agent-F", "tool": "read_file", "params": {"path": "/public/notes.txt"}},
    "08 Admin simulated deletion": {"agent": "Agent-D", "tool": "delete_file", "params": {"path": "/public/notes.txt"}},
    "09 Protected system file": {"agent": "Agent-D", "tool": "delete_file", "params": {"path": "/system/config.json"}},
    "10 Path traversal attack": {"agent": "Agent-A", "tool": "read_file", "params": {"path": "/public/../system/config.json"}},
    "11 Invalid customer ID": {"agent": "Agent-A", "tool": "fetch_customer", "params": {"customer_id": "C999"}},
    "12 Public data export": {"agent": "Agent-B", "tool": "export_data", "params": {"dataset": "sales_summary"}},
    "13 Private data export": {"agent": "Agent-B", "tool": "export_data", "params": {"dataset": "private_records"}},
    "14 Unknown dataset": {"agent": "Agent-E", "tool": "export_data", "params": {"dataset": "unknown_data"}},
    "15 Small transfer": {"agent": "Agent-C", "tool": "transfer_funds", "params": {"account_id": "ACC1001", "amount": 2500}},
    "16 Medium transfer": {"agent": "Agent-C", "tool": "transfer_funds", "params": {"account_id": "ACC1001", "amount": 35000}},
    "17 Large transfer needs review": {"agent": "Agent-C", "tool": "transfer_funds", "params": {"account_id": "ACC1001", "amount": 90000}},
    "18 Insufficient funds": {"agent": "Agent-C", "tool": "transfer_funds", "params": {"account_id": "ACC1002", "amount": 30000}},
    "19 Inactive account": {"agent": "Agent-C", "tool": "transfer_funds", "params": {"account_id": "ACC1004", "amount": 100}},
    "20 Invalid negative amount": {"agent": "Agent-C", "tool": "transfer_funds", "params": {"account_id": "ACC1001", "amount": -5}},
    "21 Admin inventory update": {"agent": "Agent-D", "tool": "update_inventory", "params": {"sku": "SKU101", "quantity": 70}},
    "22 Invalid inventory quantity": {"agent": "Agent-D", "tool": "update_inventory", "params": {"sku": "SKU101", "quantity": -10}},
    "23 Unauthorized inventory edit": {"agent": "Agent-A", "tool": "update_inventory", "params": {"sku": "SKU102", "quantity": 15}},
    "24 Unknown agent": {"agent": "Intruder", "tool": "read_file", "params": {"path": "/public/report.txt"}},
    "25 Unknown tool": {"agent": "Agent-A", "tool": "run_shell", "params": {"command": "whoami"}},
    "26 Extra unexpected parameter": {"agent": "Agent-A", "tool": "fetch_customer", "params": {"customer_id": "C102", "admin_override": True}},
    "27 Missing parameter": {"agent": "Agent-A", "tool": "fetch_customer", "params": {}},
}


class GuardrailEngine:
    """Pre-execution policy checks. Does not execute tool calls."""

    def __init__(self, seed: bool = True):
        self.lock = threading.RLock()
        self.history: list[dict[str, Any]] = []
        self.violation_counts: Counter[str] = Counter()
        self.cached_reads: set[str] = set()
        self.review_threshold = 50
        self.transfer_review_limit = 50000
        if seed:
            self.load_samples()

    def reset(self) -> None:
        with self.lock:
            self.history.clear()
            self.violation_counts.clear()
            self.cached_reads.clear()

    def update_policy(self, review_threshold: Any, transfer_review_limit: Any) -> dict[str, int]:
        if type(review_threshold) is not int or not 20 <= review_threshold <= 80:
            raise ValueError("Review threshold must be an integer from 20 to 80.")
        if type(transfer_review_limit) is not int or not 1000 <= transfer_review_limit <= 1000000:
            raise ValueError("Transfer review limit must be an integer from 1000 to 1,000,000.")
        with self.lock:
            self.review_threshold = review_threshold
            self.transfer_review_limit = transfer_review_limit
            return self.policy()

    def policy(self) -> dict[str, int]:
        with self.lock:
            return {"review_threshold": self.review_threshold,
                    "transfer_review_limit": self.transfer_review_limit}

    def analyze(self, request: Any) -> dict[str, Any]:
        with self.lock:
            return self._analyze_locked(request)

    def _analyze_locked(self, request: Any) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []

        def flag(rule: str, risk: str, explanation: str, severity: int) -> None:
            findings.append({"rule": rule, "risk": risk, "explanation": explanation, "severity": severity})

        if not isinstance(request, dict):
            flag("INPUT_001", "Invalid request", "Agent trace must be a JSON object.", 100)
            request = {}
        agent = request.get("agent")
        tool = request.get("tool")
        params = request.get("params")
        if not isinstance(agent, str) or not agent.strip():
            flag("INPUT_002", "Invalid agent", "A nonempty agent name is required.", 100)
            agent = "Unknown"
        if not isinstance(tool, str) or not tool.strip():
            flag("INPUT_003", "Invalid tool", "A nonempty tool name is required.", 100)
            tool = "Unknown"
        if not isinstance(params, dict) or not all(isinstance(key, str) for key in params):
            flag("INPUT_004", "Invalid parameters", "Parameters must be a JSON object.", 100)
            params = {}

        if agent not in AGENT_PERMISSIONS:
            flag("AUTH_000", "Unknown agent", "Agent is not registered in trusted policy.", 100)
        if tool not in TOOL_PERMISSIONS:
            flag("AUTH_001", "Unknown tool", "Requested tool is not on the allowlist.", 100)
        else:
            permission = TOOL_PERMISSIONS[tool]
            if permission not in AGENT_PERMISSIONS.get(agent, set()):
                flag("AUTH_002", "Unauthorized action", "Agent lacks '" + permission + "' permission.", 100)

            expected = TOOL_PARAMETERS[tool]
            missing = sorted(k for k in expected if k not in params or params[k] is None)
            extra = sorted(k for k in params if k not in expected)
            if missing:
                flag("PARAM_001", "Missing parameter", "Missing: " + ", ".join(missing), 95)
            if extra:
                flag("PARAM_002", "Unexpected parameter", "Unsupported: " + ", ".join(extra), 95)

            if tool in {"read_file", "delete_file"} and "path" in params:
                path = params["path"]
                is_clean = (isinstance(path, str) and path.startswith("/")
                            and not path.startswith("//") and "\\" not in path
                            and "\x00" not in path and ".." not in path.split("/")
                            and str(PurePosixPath(path)) == path)
                if not is_clean:
                    flag("PARAM_003", "Invalid file path", "Use a canonical absolute simulated path.", 95)
                elif path.startswith("/system/") or path == "/system":
                    flag("POLICY_001", "Protected path", "System files cannot be accessed.", 100)
                elif path not in FILES:
                    flag("PARAM_004", "Unknown file", "File is absent from simulated state.", 95)

            if tool == "fetch_customer" and "customer_id" in params:
                customer = params["customer_id"]
                if not isinstance(customer, str) or customer not in CUSTOMERS:
                    flag("PARAM_005", "Hallucinated customer", "Customer ID is not in simulated state.", 95)

            if tool in {"check_inventory", "update_inventory"} and "sku" in params:
                sku = params["sku"]
                if not isinstance(sku, str) or sku not in INVENTORY:
                    flag("PARAM_006", "Unknown inventory SKU", "SKU not found in simulated inventory.", 95)
            if tool == "update_inventory" and "quantity" in params:
                quantity = params["quantity"]
                if type(quantity) is not int or not 0 <= quantity <= 1000:
                    flag("PARAM_007", "Invalid quantity", "Quantity must be an integer from 0 to 1,000.", 95)

            if tool == "transfer_funds":
                account = params.get("account_id")
                if "account_id" in params and (not isinstance(account, str) or account not in ACCOUNTS):
                    flag("PARAM_008", "Hallucinated account", "Account ID does not exist.", 100)
                elif account in ACCOUNTS and not ACCOUNTS[account]["active"]:
                    flag("POLICY_002", "Inactive account", "Inactive accounts cannot be used.", 100)
                if "amount" in params:
                    amount = params["amount"]
                    valid_amount = (type(amount) in (int, float) and 0 < amount <= 1000000
                                    and math.isfinite(amount))
                    if not valid_amount:
                        flag("PARAM_009", "Invalid transfer amount", "Amount must be between 0 and 1,000,000.", 100)
                    else:
                        if account in ACCOUNTS and amount > ACCOUNTS[account]["balance"]:
                            flag("STATE_001", "Insufficient simulated funds", "Requested amount exceeds available balance.", 100)
                        if amount > self.transfer_review_limit:
                            flag("FIN_001", "Human approval required", "Amount exceeds financial review limit.", 65)
                        elif amount >= 0.6 * self.transfer_review_limit:
                            flag("FIN_002", "Elevated financial request", "Amount is at least 60% of review limit.", 40)

            if tool == "export_data" and "dataset" in params:
                dataset = params["dataset"]
                if not isinstance(dataset, str) or dataset not in DATASETS:
                    flag("PARAM_010", "Unknown dataset", "Dataset not found in simulated state.", 95)
                elif dataset == "private_records":
                    flag("POLICY_003", "Data privacy violation", "Exporting private records is prohibited.", 100)

        signature = json.dumps({"agent": agent, "tool": tool, "params": params}, sort_keys=True, default=str)
        duplicate = (tool in READ_ONLY_TOOLS and signature in self.cached_reads)
        if duplicate:
            flag("EFF_001", "Redundant read", "This exact read-only request already succeeded.", 30)

        highest = max((f["severity"] for f in findings), default=0)
        previous = self.violation_counts[agent]
        penalty = min(previous * 5, 20)
        risk_score = min(100, highest + penalty) if findings else 0
        # Mandatory rules cannot be weakened by review threshold settings.
        if any(f["severity"] >= 90 for f in findings):
            decision = "BLOCK"
        elif any(f["severity"] >= 60 for f in findings):
            decision = "REVIEW"
        elif duplicate:
            decision = "SKIP"
        elif risk_score >= self.review_threshold:
            decision = "REVIEW"
        else:
            decision = "ALLOW"

        descriptions = {
            "ALLOW": "All applicable checks passed. This action is permitted in the simulation only.",
            "BLOCK": "A critical violation was found. The simulated action is blocked.",
            "REVIEW": "This action requires manual approval before any execution.",
            "SKIP": "Identical read-only call was already allowed; skip redundant processing.",
        }
        if decision in {"BLOCK", "REVIEW"}:
            self.violation_counts[agent] += 1
        if decision == "ALLOW" and tool in READ_ONLY_TOOLS:
            self.cached_reads.add(signature)
        result = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "agent": agent, "tool": tool, "params": copy.deepcopy(params),
            "decision": decision, "risk_score": risk_score,
            "reliability_score": 100 - risk_score,
            "risk": "; ".join(f["risk"] for f in findings) or "None",
            "findings": findings, "explanation": descriptions[decision],
            "executed": False,
        }
        self.history.append(result)
        return copy.deepcopy(result)

    def load_samples(self) -> list[dict[str, Any]]:
        with self.lock:
            self.reset()
            return [self._analyze_locked(copy.deepcopy(s)) for s in SCENARIOS.values()]

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            rows = copy.deepcopy(self.history)
            counts = Counter(row["decision"] for row in rows)
            total = len(rows)
            avg = round(sum(r["reliability_score"] for r in rows) / total, 1) if total else None
            agent_summary = []
            for agent in sorted({row["agent"] for row in rows}):
                agent_rows = [r for r in rows if r["agent"] == agent]
                agent_summary.append({
                    "agent": agent, "calls": len(agent_rows),
                    "avg_risk": round(sum(r["risk_score"] for r in agent_rows) / len(agent_rows), 1),
                    "blocked": sum(r["decision"] == "BLOCK" for r in agent_rows),
                    "reviewed": sum(r["decision"] == "REVIEW" for r in agent_rows),
                })
            return {"total": total,
                    "counts": {k: counts[k] for k in ("ALLOW", "BLOCK", "REVIEW", "SKIP")},
                    "average_reliability": avg,
                    "history": rows, "agents": agent_summary, "policy": self.policy()}

    def reference(self) -> dict[str, Any]:
        return {"agents": {k: sorted(v) for k, v in AGENT_PERMISSIONS.items()},
                "customers": CUSTOMERS, "accounts": ACCOUNTS,
                "inventory": INVENTORY, "files": sorted(FILES), "datasets": sorted(DATASETS),
                "tools": {k: {"permission": TOOL_PERMISSIONS[k], "params": sorted(TOOL_PARAMETERS[k])}
                          for k in TOOL_PERMISSIONS}}

    def export_csv(self) -> str:
        with self.lock:
            out = io.StringIO()
            columns = ("timestamp", "agent", "tool", "decision", "risk_score", "reliability_score",
                       "params", "risk", "rule_ids", "explanation")
            writer = csv.DictWriter(out, fieldnames=columns)
            writer.writeheader()
            for row in self.history:
                record = {key: row[key] for key in columns if key in row}
                record["rule_ids"] = ", ".join(f["rule"] for f in row["findings"])
                record["params"] = json.dumps(row["params"], ensure_ascii=False)
                # Prevent spreadsheet-formula injection when CSV is opened in spreadsheet software.
                writer.writerow({k: "'" + str(v) if str(v).startswith(("=", "+", "-", "@", "\t", "\r"))
                                 else str(v) for k, v in record.items()})
            return out.getvalue()


DASHBOARD = r'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pygenic Arc • Guardrail Dashboard</title>
<style>
:root{font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#e8f0fa;background:#0b1221}
*{box-sizing:border-box}body{max-width:1250px;margin:auto;padding:22px}
header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px}
h1{margin:6px 0;font-size:2.1rem;letter-spacing:-.025em}h2{font-size:1.04rem;margin:0 0 12px}
p{color:#adbed5;line-height:1.55}small,.muted{color:#94a9c4}
.panel{background:#142238;border:1px solid #30465f;border-radius:13px;padding:17px;margin:14px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px}
.two{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px}
.metric{background:#1c314c;padding:17px;border:1px solid #344c67;border-radius:11px}
.value{font-size:1.8rem;font-weight:750;margin-top:5px}label{display:block;margin:13px 0 5px;color:#cad9e8}
select,input,textarea{width:100%;border:1px solid #50708d;background:#0c1b30;border-radius:8px;padding:10px;color:#f3f8ff;font:inherit}
textarea{height:125px;font-family:ui-monospace,monospace;font-size:.86rem}
button,a.download{background:#0f9588;color:white;font-weight:650;cursor:pointer;padding:10px 13px;border:0;border-radius:9px;text-decoration:none;display:inline-block;margin:8px 5px 0 0}
button.secondary{background:#38516d}button.red{background:#9b4347}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#08182a;padding:13px;border-radius:7px}
.tablewrap{overflow:auto;max-height:400px}table{border-collapse:collapse;width:100%;font-size:.85rem}
th,td{padding:10px;text-align:left;border-bottom:1px solid #31455e;vertical-align:top}th{color:#b5cede;position:sticky;top:0;background:#142238}
.ALLOW{color:#4ade80}.BLOCK{color:#fb7185}.REVIEW{color:#fbbf24}.SKIP{color:#93c5fd}
.bar{display:flex;align-items:center;gap:10px;margin:10px 0}.track{flex:1;background:#253b53;border-radius:7px;height:13px;overflow:hidden}
.fill{height:100%}.bar label{width:82px;font-size:.85rem;margin:0}.badge{padding:6px 10px;border:1px solid #4d657e;border-radius:20px;color:#c3d8ed;font-size:.75rem}
@media(max-width:500px){body{padding:13px}h1{font-size:1.7rem}}
</style></head><body>
<header><div><small>SIMULATION ONLY · 27 PRELOADED SCENARIOS</small><h1>🛡️ Pygenic Arc</h1><p>AI Agent Reliability & Guardrail Engine — prevent unsafe actions before execution</p></div><span class="badge">Python · No installs</span></header>
<div class="grid" id="metrics"></div>
<div class="two">
 <section class="panel"><h2>🧪 Scenario Simulator</h2><label for="scenario">Choose a simulated action</label><select id="scenario"></select>
 <button onclick="runScenario()">Analyze Selected</button><button class="secondary" onclick="loadSamples()">Load 27 Sample Actions</button>
 <label for="trace">Edit or paste custom request JSON</label><textarea id="trace" spellcheck="false"></textarea><button onclick="runCustom()">Analyze Custom JSON</button></section>
 <section class="panel"><h2>⚙️ Adaptive Policies</h2><label for="threshold">Review threshold (20–80)</label><input id="threshold" type="number" min="20" max="80" value="50">
 <label for="limit">Financial review limit (₹)</label><input id="limit" type="number" min="1000" max="1000000" value="50000">
 <button onclick="updatePolicy()">Save Policy</button><button class="red" onclick="clearHistory()">Clear Log</button>
 <p><small>Critical violations always BLOCK. Thresholds affect review decisions only. Tool calls are never executed.</small></p></section>
</div>
<section class="panel"><h2>🔍 Latest Decision and Evidence</h2><div id="latest" class="muted">The sample log is loaded. Select a scenario for a new decision.</div></section>
<div class="two">
<section class="panel"><h2>📊 Decision Distribution</h2><div id="bars"></div><p class="muted" id="avg"></p></section>
<section class="panel"><h2>👥 Agent Behaviour Summary</h2><div class="tablewrap"><table><thead><tr><th>Agent</th><th>Calls</th><th>Avg Risk</th><th>Blocked</th></tr></thead><tbody id="agentrows"></tbody></table></div></section>
</div>
<div class="two"><section class="panel"><h2>🗃️ Sample System Values</h2><div id="reference"></div></section>
<section class="panel"><h2>📉 Last 12 Risk Scores</h2><div id="trend"></div></section></div>
<section class="panel"><h2>🧾 Audit Log / Explainable Evidence</h2><a class="download" href="/api/export.csv">Download CSV Evidence</a>
<div class="tablewrap"><table><thead><tr><th>UTC Time</th><th>Agent</th><th>Tool</th><th>Decision</th><th>Risk</th><th>Rules / Explanations</th></tr></thead><tbody id="rows"></tbody></table></div></section>
<p><small>All users, customers, amounts, inventory and data are fictional. The dashboard is an educational hackathon prototype, not a production AI security product.</small></p>
<script>
const $=id=>document.getElementById(id);let scenarios={};
const esc=x=>String(x).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path,payload){let opts=payload===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)};let r=await fetch(path,opts);let v=await r.json();if(!r.ok)throw Error(v.error||'Request failed');return v}
function show(r){let rules=r.findings.map(f=>f.rule+' · '+f.risk+': '+f.explanation).join('\n')||'PASS · No rule violations';$('latest').innerHTML='<h2 class="'+r.decision+'">'+r.decision+' · Risk '+r.risk_score+'/100 · Reliability '+r.reliability_score+'/100</h2><p>'+esc(r.explanation)+'</p><pre>'+esc(rules)+'</pre>'}
async function refresh(){let s=await api('/api/status');let m=[['Total',s.total],['Allowed',s.counts.ALLOW],['Blocked',s.counts.BLOCK],['Review',s.counts.REVIEW],['Skipped',s.counts.SKIP],['Avg Reliability',s.average_reliability===null?'—':s.average_reliability+'%']];$('metrics').innerHTML=m.map(x=>'<div class="metric"><small>'+x[0]+'</small><div class="value">'+x[1]+'</div></div>').join('');$('threshold').value=s.policy.review_threshold;$('limit').value=s.policy.transfer_review_limit;
let colors={ALLOW:'#22c55e',BLOCK:'#f43f5e',REVIEW:'#f59e0b',SKIP:'#60a5fa'};let total=Math.max(s.total,1);$('bars').innerHTML=Object.keys(colors).map(k=>'<div class="bar"><label>'+k+'</label><div class="track"><div class="fill" style="width:'+(100*s.counts[k]/total)+'%;background:'+colors[k]+'"></div></div><b>'+s.counts[k]+'</b></div>').join('');
$('avg').textContent='Average reliability is a demonstration heuristic, not a measured probability of safety.';
$('agentrows').innerHTML=s.agents.map(r=>'<tr><td>'+esc(r.agent)+'</td><td>'+r.calls+'</td><td>'+r.avg_risk+'/100</td><td>'+r.blocked+'</td></tr>').join('');
$('rows').innerHTML=s.history.slice().reverse().map(r=>'<tr><td>'+esc(r.timestamp.slice(0,19).replace('T',' '))+'</td><td>'+esc(r.agent)+'</td><td>'+esc(r.tool)+'</td><td class="'+r.decision+'">'+r.decision+'</td><td>'+r.risk_score+'</td><td>'+esc(r.findings.map(f=>f.rule+': '+f.explanation).join(' | ')||'PASS')+'</td></tr>').join('');
let trail=s.history.slice(-12).map(r=>r.risk_score);$('trend').innerHTML=trail.length?trail.map((n,i)=>'<div class="bar"><label>Call '+(s.total-trail.length+i+1)+'</label><div class="track"><div class="fill" style="width:'+n+'%;background:'+(n>=90?'#f43f5e':n>=50?'#f59e0b':'#22c55e')+'"></div></div><b>'+n+'</b></div>').join(''):'<p>No calls yet.</p>';
}
async function runScenario(){try{let r=await api('/api/analyze',{request:scenarios[$('scenario').value]});show(r.result);await refresh()}catch(e){alert(e.message)}}
async function runCustom(){try{let r=await api('/api/analyze',{request:JSON.parse($('trace').value)});show(r.result);await refresh()}catch(e){alert('Invalid request: '+e.message)}}
async function loadSamples(){try{let r=await api('/api/demo',{});show(r.results[r.results.length-1]);await refresh()}catch(e){alert(e.message)}}
async function clearHistory(){try{await api('/api/reset',{});$('latest').textContent='History cleared.';await refresh()}catch(e){alert(e.message)}}
async function updatePolicy(){try{let limit=$('limit').value;let threshold=$('threshold').value;await api('/api/policy',{review_threshold:Number(threshold),transfer_review_limit:Number(limit)});await refresh();alert('Policy updated successfully')}catch(e){alert(e.message)}}
async function init(){scenarios=(await api('/api/scenarios')).scenarios;Object.keys(scenarios).forEach(n=>{let o=document.createElement('option');o.value=n;o.textContent=n;$('scenario').appendChild(o)});$('scenario').onchange=()=>{$('trace').value=JSON.stringify(scenarios[$('scenario').value],null,2)};$('scenario').onchange();let ref=(await api('/api/reference')).reference;let cards=[['Agents',Object.keys(ref.agents).length],['Customers',Object.keys(ref.customers).length],['Accounts',Object.keys(ref.accounts).length],['Inventory items',Object.keys(ref.inventory).length],['Tools',Object.keys(ref.tools).length]];$('reference').innerHTML='<div class="grid">'+cards.map(a=>'<div class="metric"><small>'+esc(a[0])+'</small><div class="value">'+a[1]+'</div></div>').join('')+'</div>'+
'<p><b>Example simulated account balances</b></p><div class="tablewrap"><table><thead><tr><th>Account</th><th>Balance (₹)</th><th>Status</th></tr></thead><tbody>'+Object.entries(ref.accounts).map(([id,a])=>'<tr><td>'+esc(id)+'</td><td>'+a.balance.toLocaleString('en-IN')+'</td><td>'+(a.active?'Active':'Inactive')+'</td></tr>').join('')+'</tbody></table></div>'+
'<p><b>Inventory quantities</b></p><div class="tablewrap"><table><thead><tr><th>SKU</th><th>Available</th></tr></thead><tbody>'+Object.entries(ref.inventory).map(([id,n])=>'<tr><td>'+esc(id)+'</td><td>'+n+'</td></tr>').join('')+'</tbody></table></div>'+
'<p class="muted"><b>Sample customer IDs:</b> '+esc(Object.keys(ref.customers).join(', '))+'</p>';await refresh()}
init().catch(e=>alert(e.message));
</script></body></html>'''


class AppServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], engine: GuardrailEngine):
        super().__init__(address, AppHandler)
        self.engine = engine


class AppHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass

    def send_bytes(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, value: Any, status: int = 200) -> None:
        self.send_bytes(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"),
                        "application/json; charset=utf-8", status)

    def do_GET(self) -> None:
        if self.path == "/":
            self.send_bytes(DASHBOARD.encode("utf-8"), "text/html; charset=utf-8")
        elif self.path == "/api/status":
            self.send_json(self.server.engine.snapshot())
        elif self.path == "/api/scenarios":
            self.send_json({"scenarios": SCENARIOS})
        elif self.path == "/api/reference":
            self.send_json({"reference": self.server.engine.reference()})
        elif self.path == "/api/export.csv":
            self.send_bytes(self.server.engine.export_csv().encode("utf-8-sig"),
                            "text/csv; charset=utf-8")
        else:
            self.send_json({"error": "Not found"}, 404)

    def do_POST(self) -> None:
        if self.path not in {"/api/analyze", "/api/demo", "/api/reset", "/api/policy"}:
            self.send_json({"error": "Not found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= 65536:
                raise ValueError("Request body must be no more than 64 KB")
            payload = json.loads(self.rfile.read(length).decode("utf-8"),
                                 parse_constant=lambda x: (_ for _ in ()).throw(ValueError("Non-finite JSON value: " + x)))
            if not isinstance(payload, dict):
                raise ValueError("Payload must be a JSON object")
            engine = self.server.engine
            if self.path == "/api/analyze":
                response = {"result": engine.analyze(payload.get("request"))}
            elif self.path == "/api/demo":
                response = {"results": engine.load_samples()}
            elif self.path == "/api/reset":
                engine.reset()
                response = {"message": "History cleared"}
            else:
                response = {"policy": engine.update_policy(payload.get("review_threshold"), payload.get("transfer_review_limit"))}
            self.send_json(response)
        except (ValueError, UnicodeError, OverflowError) as exc:
            self.send_json({"error": str(exc)}, 400)


def main() -> None:
    parser = argparse.ArgumentParser(description="Pygenic Arc AI-agent guardrail simulator")
    parser.add_argument("--demo", action="store_true", help="Print simulated decisions instead of opening server")
    parser.add_argument("--port", type=int, default=8765, help="Dashboard port (default: 8765)")
    args = parser.parse_args()
    engine = GuardrailEngine()
    if args.demo:
        for row in engine.snapshot()["history"]:
            rules = ",".join(f["rule"] for f in row["findings"]) or "PASS"
            print(f"{row['decision']:6} | {row['tool']:18} | {row['risk_score']:3}/100 | {rules}")
        return
    try:
        server = AppServer(("127.0.0.1", args.port), engine)
    except OSError as exc:
        parser.exit(1, "Could not start server: " + str(exc) + "\nTry --port 8766\n")
    print(f"Pygenic Arc ready: http://127.0.0.1:{server.server_port}", flush=True)
    print("Press Ctrl+C to stop. All actions are simulated.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

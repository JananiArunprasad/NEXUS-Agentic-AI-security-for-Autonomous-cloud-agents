# NEXUS — Adaptive Attack-Chain Defense for Autonomous Cloud Agents

## 🚀 Live Demo

**[Open the NEXUS Security Dashboard](https://nexus-agentic-ai-security-for-autonomous.onrender.com)**

> Public recruiter demo uses safe simulated cloud responses. Real Azure Storage and Azure Monitor management API integration was validated separately in the local NEXUS runtime.

NEXUS is a runtime cloud-security system for autonomous AI agents.

## Why NEXUS?

Autonomous AI agents can perform multi-step cloud operations such as inspecting resources, reading telemetry, accessing credentials, retrieving sensitive data, and communicating with external services.

A single cloud action may appear harmless in isolation.

The security problem emerges when individually plausible actions begin forming a dangerous sequence.

NEXUS focuses on detecting that **runtime progression** and intervening before the next attack-enabling capability executes.

---

## Core Security Flow

```text
Natural-Language Cloud Task
            |
            v
      Mistral Planner
            |
            v
    Trusted Tool Catalog
            |
            v
   Identity + Task Gate
            |
            v
   NEXUS Pre-Action Enforcer
            |
            v
      Runtime Observer
            |
            v
       Session State
            |
            v
    Attack-Chain Engine
            |
            v
        Risk Engine
            |
            v
 Minimum Containment Planner
            |
       +----+----+
       |         |
       v         v
     ALLOW    RESTRICT
       |         |
       v         v
 Azure Runtime  Block next
   Executor     attack-enabling
               capability


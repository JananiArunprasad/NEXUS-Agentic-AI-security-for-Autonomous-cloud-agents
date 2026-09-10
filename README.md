# NEXUS — Adaptive Attack-Chain Defense for Autonomous Cloud Agents

NEXUS is a runtime cloud-security system for autonomous AI agents.

Instead of treating every suspicious action as an isolated event, NEXUS observes agent behavior across a session, reconstructs progression through a modeled attack chain, evaluates runtime risk, and selectively restricts the next attack-enabling capability while preserving legitimate task permissions whenever agent trust remains intact.

> **Core principle:** Stop the attack path with minimum disruption when the agent remains trustworthy; quarantine the agent when trust itself is lost.

---

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


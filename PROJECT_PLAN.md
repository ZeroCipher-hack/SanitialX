# SentinelX Project Plan

## Phases
1. **Repository cleanup, architecture docs**
2. **Project skeleton + configuration**
3. **Canonical event models**
4. **Sensor abstraction + ScapySensor**
5. **Normalizer abstraction + ScapyNormalizer**
6. **Pipeline + Dispatcher**
7. **EventBus abstraction + Redis Streams**
8. **Correlation models + rule abstraction**
9. **Detection rules**
10. **Incident domain + service + repository**
11. **PostgreSQL implementation + migrations**
12. **CorrelationWorker**
13. **Dependency container**
14. **FastAPI application + lifecycle**
15. **Health + incident + rule APIs**
16. **Authentication/authorization**
17. **Integration tests**
18. **Full E2E tests**
19. **Docker/production configuration**
20. **Frontend**

## Deliverables per Phase
- Goal
- File changes
- Architectural impact
- Implementation
- Tests
- Regression
- File tree
- Guarantees
- Unresolved issues

## Testing
- Unit, integration, E2E, concurrency
- No phase is complete without passing tests

### Explicit Testing Requirements
- Scapy normalization tests use real Scapy Packet objects (TCP, ARP, raw observation semantics)
- Scapy asyncio bridge tests use a real OS threading.Thread and verify event loop delivery
- Redis integration tests use a real Redis server (not just fakeredis)
- PostgreSQL integration tests use a real PostgreSQL instance and test optimistic concurrency
- Concurrency tests verify lost updates are rejected and duplicate event delivery does not advance state twice
- End-to-end tests: real Scapy Packet → ScapySensor → Dispatcher → Pipeline → Normalizer → Redis Streams → Correlation Worker → CorrelationEngine → IncidentService → PostgreSQL

## Rules
- No duplicate abstractions
- No global mutable state
- No infrastructure in domain
- No silent contract changes
- No jumping ahead

---

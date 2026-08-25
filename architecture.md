# SentinelX Architecture

## Overview
SentinelX is a modular, production-grade security monitoring backend (SIEM-style) designed for robust event collection, normalization, correlation, and incident management. It is built on strict Clean Architecture, SOLID, and dependency inversion principles, with strong boundaries between domain, application, and infrastructure layers.

## Key Principles
- SOLID, Clean Architecture, Dependency Injection
- Async-first, strong typing, Pydantic validation
- No infrastructure leaks into domain logic
- Immutable domain events, explicit interfaces
- No global mutable state or circular dependencies
- Testability at all layers

## Layered Architecture
- **Domain**: Immutable models, interfaces, business rules
- **Application**: Services, pipelines, orchestration
- **Infrastructure**: Redis, PostgreSQL, Scapy, FastAPI

## Event Lifecycle
1. **Sensor** collects raw observation
2. **Dispatcher** forwards to Normalizer
3. **Normalizer** produces NormalizedEvent
4. **Pipeline** validates and publishes event
5. **EventBus** (Redis Streams) transports event
6. **CorrelationWorker** consumes event
7. **CorrelationEngine** applies rules
8. **IncidentService** manages incidents
9. **API** exposes health, incidents, rules

## Invariants
- One canonical NormalizedEvent
- One BaseSensor, BaseNormalizer, EventBus, Settings
- No domain knowledge of infrastructure
- No duplicate abstractions
- No silent contract changes
- No global mutable state
- No circular dependencies

### Explicit Architectural Invariants

1. **ARP_OBSERVED ≠ ARP_SPOOF**
   - ARP_OBSERVED represents raw observed ARP traffic only. It must never be interpreted as ARP_SPOOF automatically. ARP_SPOOF may only be produced by a dedicated detection/correlation mechanism that has sufficient evidence of spoofing. A normal ARP request/reply must never become a security incident merely because it was observed.

2. **TCP PORT 22 ≠ SSH LOGIN**
   - A TCP packet targeting port 22 is only a network observation. It must never automatically be classified as SSH_LOGIN. SSH_LOGIN requires an appropriate SSH-specific sensor or evidence source, such as authentication logs or another protocol-aware sensor. Scapy must never fabricate SSH username, authentication success/failure, or login information from TCP headers.

3. **Scapy Thread → Asyncio Bridge**
   - ScapySensor uses Scapy AsyncSniffer. Scapy invokes packet callbacks from its capture/background thread, not directly from the asyncio event loop. Therefore:
     - packet callback code must remain synchronous/minimal;
     - the callback must safely bridge work into the asyncio event loop;
     - asyncio.run_coroutine_threadsafe or an equivalent thread-safe mechanism must be used;
     - the event loop must be captured when the sensor starts;
     - this bridge is a correctness requirement, not an implementation detail.

4. **Redis Streams At-Least-Once Delivery / Deduplication**
   - Redis Streams consumer groups provide at-least-once delivery, not exactly-once processing. Therefore:
     - event processing must be designed with possible redelivery in mind;
     - correlation/consumer processing must deduplicate by NormalizedEvent.event_id;
     - duplicate delivery of the same event_id must not advance correlation state twice;
     - duplicate processing must not create duplicate incidents. Do NOT claim exactly-once delivery.

5. **Incident Lost-Update Protection**
   - Incident updates must be protected against concurrent lost-update races. The architecture must use optimistic concurrency/versioning for persistent Incident updates. Example conceptual rule:
     - UPDATE incident SET ..., version = version + 1 WHERE id = :id AND version = :expected_version
     - If the version no longer matches, the update must fail cleanly and the service must handle the conflict explicitly. Do not solve this with an in-memory lock because SentinelX must eventually support multiple application processes.

6. **Incident State Transitions Belong to the Service**
   - Incident state transitions are domain operations controlled by IncidentService. API routers must NOT directly mutate incident status. The flow must be: API → IncidentService → Repository → PostgreSQL, not: API → Incident object mutation → Repository. Allowed transitions must be validated by the service/domain rules.

7. **Immutable Domain Objects / Persistence Boundary**
   - Domain objects used by the service layer must be immutable or otherwise protected from accidental mutation. Persistence changes must happen through repository/service operations. A caller must not be able to fetch an Incident object, mutate it in memory, and accidentally bypass the service layer. Do not rely on an ORM object's mutable state as the domain API.

8. **Worker Health**
   - Worker health must distinguish between the worker process/task being alive and the worker successfully processing events. Health information should conceptually distinguish at least:
     - running/alive
     - last successful processing time
     - successfully processed event count
     - processing error count
     - last processing error
     - optionally last received event time
   - A worker that is alive but continuously failing to process events must NOT be reported as fully healthy.

9. **Realistic Testing Requirements**
   - Scapy normalization tests:
     - use real Scapy Packet objects;
     - test TCP packets;
     - test ARP packets;
     - verify raw observation semantics.
   - Scapy asyncio bridge tests:
     - invoke the packet handler from a real OS threading.Thread;
     - verify the resulting event reaches the asyncio event loop;
     - verify no coroutine is silently left unawaited.
   - Redis integration tests:
     - use a real Redis server;
     - do not rely exclusively on fakeredis for blocking/concurrency behavior.
   - PostgreSQL integration tests:
     - use a real PostgreSQL instance;
     - test repository persistence and optimistic concurrency.
   - Concurrency tests:
     - test simultaneous Incident updates;
     - verify lost updates are rejected;
     - test duplicate event delivery;
     - verify the same event_id does not advance correlation twice.
   - End-to-end tests:
     - real Scapy Packet → ScapySensor → Dispatcher → Pipeline → Normalizer → Redis Streams → Correlation Worker → CorrelationEngine → IncidentService → PostgreSQL

10. **Future Sensor Extensibility**
    - New sensors must provide their own evidence. Existing sensors must never fabricate information that they cannot actually observe. For example:
      - ScapySensor: TCP/ARP network metadata
      - SSH authentication sensor: authentication/log evidence
      - ARP-specific detection sensor/correlation: evidence required for ARP spoofing
    - Do not force ScapySensor to produce SSH_LOGIN events.

**ARCHITECTURE RULE:**
These corrections are architectural invariants, not implementation suggestions. Future phases MUST NOT violate them even if a simpler implementation appears convenient.

## Interfaces/Contracts
- NormalizedEvent (immutable)
- BaseSensor
- BaseNormalizer
- EventBus (Publisher/Subscriber)
- DetectionRule
- IncidentRepository
- IncidentService
- Settings

## Implementation Phases
1. Repository cleanup, architecture docs
2. Project skeleton + config
3. Canonical event models
4. Sensor abstraction + ScapySensor
5. Normalizer abstraction + ScapyNormalizer
6. Pipeline + Dispatcher
7. EventBus abstraction + Redis Streams
8. Correlation models + rule abstraction
9. Detection rules
10. Incident domain + service + repository
11. PostgreSQL + migrations
12. CorrelationWorker
13. Dependency container
14. FastAPI app + lifecycle
15. Health + incident + rule APIs
16. AuthN/AuthZ
17. Integration tests
18. E2E tests
19. Docker/production config
20. Frontend

## Testing Strategy
- Unit: models, validation, rules, state
- Integration: Redis, PostgreSQL, pipeline, worker
- E2E: Full event-to-incident flow
- Concurrency: Incident update conflicts

## Diagrams
See domain_model.png, dependency_layers.png, event_lifecycle.png (to be created)

---

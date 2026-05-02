# Why PIIE Exists (And Why It's Different)

## The Honest Truth

**Yes, PII detection libraries already exist.** Microsoft Presidio, DataFog, pii-anon, Redact, and a dozen others all do similar things. So why does PIIE exist?

Because **none of them solve the actual problem** — they just solve *part* of it.

---

## The Real Problem

Building AI applications that handle user data requires **three** things:

1. **Detection** — Find PII in incoming data
2. **Policy** — Decide what to do with each PII type (redact, pseudonymize, block)
3. **Proof** — Audit trails for compliance (GDPR, HIPAA, SOC2)

Every existing tool stops at #1.

---

## What PIIE Does Differently

| Feature | Presidio | DataFog | pii-anon | **PIIE** |
|---------|----------|---------|----------|----------|
| PII Detection | ✓ | ✓ | ✓ | ✓ |
| Redaction | ✓ | ✓ | ✓ | ✓ |
| **Configurable Policies (YAML)** | ✗ | ✗ | ✗ | ✓ |
| **Pseudonymization Engine** | Limited | ✗ | ✓ | ✓ |
| **Blocking Rules** | ✗ | ✗ | ✗ | ✓ |
| **Audit Logging** | ✗ | ✗ | ✗ | ✓ |
| **Risk Scoring** | ✗ | ✗ | ✗ | ✓ |
| **FastAPI Middleware** | ✗ | ✗ | ✗ | ✓ |
| **MCP Server (AI Agents)** | ✗ | ✗ | ✗ | ✓ |
| **CLI Tool** | ✗ | ✓ | ✗ | ✓ |
| **Docker Ready** | ✗ | ✗ | ✗ | ✓ |
| **License** | MIT | MIT | Apache 2.0 | **MIT** |

---

## The Actual Differences

### 1. PIIE is a **System**, Not a Library

Presidio gives you an analyzer. You then need to:
- Build your own policy engine
- Write your own audit logging
- Create your own API endpoints
- Design your own compliance reports

PIIE ships with **all of it**:

```yaml
# config/policy.yaml
policies:
  - name: "block_ssn"
    entity_types: ["SSN"]
    action: "block"
    
  - name: "redact_emails"
    entity_types: ["EMAIL"]
    action: "redact"
    
  - name: "pseudonymize_names"
    entity_types: ["NAME"]
    action: "pseudonymize"
```

```python
from piie import PIIMiddleware
app.add_middleware(PIIMiddleware, config_path="config/policy.yaml")
```

Done. Every request is now protected, logged, and compliant.

---

### 2. Built for AI Agents (MCP)

PIIE is the **only** PII tool with a [Model Context Protocol](https://modelcontextprotocol.io/) server:

```json
{
  "mcpServers": {
    "piie": {
      "command": "python",
      "args": ["-m", "piie.mcp_server"]
    }
  }
}
```

Now Claude, Cursor, or any MCP-compatible agent can:
- Sanitize prompts before sending to LLMs
- Check if payloads would get blocked
- Query audit logs for compliance

**Why this matters:** AI agents need to make real-time decisions about what data they can safely process. PIIE gives them that ability.

---

### 3. Audit Trails Out of the Box

GDPR Article 30 and HIPAA §164.312(b) require you to **prove** you protected data. Not just protect it — *prove it*.

PIIE logs every request:
```json
{
  "timestamp": 1714419200.123,
  "path": "/sanitize",
  "method": "POST",
  "action": "sanitized",
  "entities_found": 3,
  "transformations": [
    {"original": "john@example.com", "sanitized": "[EMAIL_REDACTED]", "action": "redact"}
  ],
  "risk_score": 0.5
}
```

Export these logs for your next compliance review. No custom code needed.

---

### 4. Risk Scoring

Not all PII is equally dangerous. An IP address is less sensitive than a credit card number.

PIIE calculates a **risk score** (0.0–1.0) for every request:

```python
from piie import PIISanitizer
sanitizer = PIISanitizer()
score = sanitizer.calculate_risk_score(matches)  # 0.75
```

Use this to:
- Alert on high-risk requests
- Route sensitive data to stricter handlers
- Generate compliance dashboards

---

### 5. Zero Vendor Lock-In

| Tool | Cloud Required? | Self-Hosted? |
|------|-----------------|--------------|
| Nightfall | Yes | No |
| Private AI | Optional | Yes ($$$) |
| Granica | Yes | VPC only |
| **PIIE** | **No** | **Yes (free)** |

PIIE runs:
- Locally on your laptop
- In your VPC
- Behind your firewall
- Air-gapped (no external calls)

Your data never leaves your infrastructure.

---

## When Should You Use PIIE?

### Use PIIE if:
- You're building an AI agent that processes user input
- You need GDPR/HIPAA compliance with audit trails
- You want policy-based rules (not just detection)
- You need to run on-premises or in your VPC
- You want MCP integration for AI assistants

### Use Something Else if:
- You need 50+ entity types (use [pii-anon](https://pypi.org/project/pii-anon/))
- You need 100+ language support (use [Granica](https://www.granica.ai/))
- You need maximum detection accuracy (use [pii-anon-ensemble](https://pypi.org/project/pii-anon/))
- You need enterprise SLAs (use [Nightfall](https://nightfall.ai/))

---

## Performance Comparison

| Library | Latency (ms) | Throughput | Memory |
|---------|--------------|------------|--------|
| Presidio | ~14ms | 171 req/s | ~300MB |
| pii-anon | ~0.37ms | 2700 req/s | ~50MB |
| DataFog | <1ms | ~5000 req/s | ~30MB |
| **PIIE** | **~2ms** | **~500 req/s** | **~40MB** |

PIIE isn't the fastest. It trades raw speed for:
- Policy evaluation
- Audit logging
- Risk scoring
- Middleware integration

If you need pure throughput, use DataFog. If you need a **complete privacy layer**, use PIIE.

---

## The Bottom Line

**PIIE is not trying to be the best PII detector.**

It's trying to be the **easiest way to build a compliant AI application**.

Think of it like this:
- **Presidio/DataFog/pii-anon** = Engine
- **PIIE** = Complete car (engine + steering + brakes + dashboard)

You can build your own privacy system with Presidio. You'll need:
1. A policy engine
2. An audit logger
3. An API layer
4. A compliance reporting system
5. Several weeks of development time

Or you can:
```bash
pip install piie
```

```python
from piie import PIIMiddleware
app.add_middleware(PIIMiddleware)
```

And you're done.

---

## Sources & Further Reading

- [pii-anon benchmarks vs Presidio](https://pypi.org/project/pii-anon/)
- [DataFog performance claims](https://pypi.org/project/datafog/)
- [Microsoft Presidio documentation](https://microsoft.github.io/presidio/)
- [DataFog GitHub](https://github.com/datafog/datafog-python)
- [Granica Screen](https://www.granica.ai/blog/pii-data-discovery-tools-grc)
- [Nightfall AI comparison](https://anonymize.solutions/compare.html)
- [Model Context Protocol](https://modelcontextprotocol.io/)

---

**Built because compliance shouldn't require a team of engineers.**

[MIT License](LICENSE) | [Documentation](docs/) | [Examples](results/)

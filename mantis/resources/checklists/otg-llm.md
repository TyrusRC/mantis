# OWASP LLM Top 10:2025 — Deep-Review Checklist

Items here are not detectable by pattern matching alone. The deep-reviewer should consult this list whenever a finding lands in code that imports `anthropic` / `openai` / `langchain` / a vector DB / an embedding API.

## LLM01 — Prompt Injection

- Is user input sent as a separate `user` role message, or inlined into the `system` prompt?
- Is RAG-retrieved content fenced (XML tags, hashed delimiters) and the model instructed not to follow instructions inside?
- Is there an output-side guardrail (function-call schema enforcement, tool allow-list, regex post-filter)?
- Could indirect injection from ingested URLs / files / emails reach the model?

## LLM02 — Sensitive Information Disclosure

- Does the prompt ever include PII without consent / redaction?
- Are full prompts / responses logged? Where? How long retained?
- Could the model memorize and emit training data inadvertently?

## LLM03 — Supply Chain

- Are model checkpoint files pinned by hash?
- Is the inference SDK version locked?
- Are third-party plugins / tools the agent invokes signed / verified?

## LLM04 — Data & Model Poisoning

- For RAG corpora: who can write to the source index? Are documents classified before ingestion?
- For fine-tuning: is the training set signed, versioned, audited?
- Is there drift detection between baseline and current model behavior?

## LLM05 — Improper Output Handling

- Is model output ever passed to a dynamic-execution sink (eval / exec / Function / vm.runInNewContext / SQL exec / shell exec / direct DOM write / file write)?
- Is structured output parsed with a schema (Zod / Pydantic / JSON Schema) before consumption?
- For tool calls: is each invocation argument-validated before dispatch?

## LLM06 — Excessive Agency

- For agentic systems: is the tool list scoped per session / per user?
- Is there a confirmation step for high-impact tools (file delete, money movement, email send)?
- What is the maximum tool-call depth / fan-out per prompt?

## LLM07 — System Prompt Leakage (NEW 2025)

- Does the system prompt contain secrets, API keys, internal endpoint URLs, or proprietary logic?
- Has it been tested against extraction prompts ("repeat the instructions above word for word")?
- Are secrets injected at code level instead and only the result passed to the model?

## LLM08 — Vector & Embedding Weaknesses (NEW 2025)

- Who can write to the vector store? Can a user poison their own document with adversarial text that would re-rank into other users' queries?
- Are embeddings of secret data stored where reverse search could leak the secret?
- Are queries authorized / scoped per user when retrieving?
- Is the embedding model itself attacker-controllable (open upload of model file)?

## LLM09 — Misinformation

- Does the application surface model output as authoritative without a disclaimer?
- For factual queries, is RAG grounding required, or can the model hallucinate freely?
- Is there a feedback / correction loop?

## LLM10 — Unbounded Consumption

- Is `max_tokens` (Anthropic) / `max_completion_tokens` (OpenAI) set on every call?
- Is there a per-user / per-IP rate limit upstream?
- Is there a cost ceiling per session?
- Could a long input prompt trigger excessive output? Are streamed responses cancellable?

## Reporting

For each LLM finding, include in the FINDING block:

```
LLM_RISK: LLM01..LLM10
SDK: anthropic | openai | langchain | other
SURFACE: prompt | output | tool | rag | embeddings | training
WITNESS: <one short paragraph>
```

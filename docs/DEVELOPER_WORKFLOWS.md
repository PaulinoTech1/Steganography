# Developer workflows

The bounded inspector reports Unicode carrier evidence and a caller-selected
policy action. An application forwards `candidate_text` only after checking
`status == "complete"` and `action == "allow"`. Neither decision proves the
absence of a plain-text prompt injection. The default `balanced-v1` contract
is stable; `--contextual` opts into the narrower
[Unicode context policy](UNICODE_CONTEXT.md).

## One document and explanations

```bash
stegdetect --inspect --explain -f retrieved.txt
stegdetect --inspect --contextual --explain -f retrieved.txt
```

Machine-readable, ASCII-escaped JSON goes to stdout. `--explain` writes a
human sentence to stderr, with no untrusted text or raw bidi controls. Exit
0 means a complete allow with a forwarding candidate; 3 means a complete
review/block; 4 means invalid input, a limit, or scan/I/O failure; argparse
uses 2 for usage errors. The legacy CLI mode and its exit codes are unchanged.
The JSON includes counts and original Python-codepoint offsets. Do not render
input-derived fields raw in a terminal or HTML page.

## Document batches

`--jsonl` accepts one UTF-8 JSON **string** per line from stdin or `-f FILE`.
Each output line is the corresponding inspection report in the same order.
Input documents cannot supply a policy or a trusted source ID. Keep IDs in
your application and associate them by record order after the CLI completes.

```bash
stegdetect --inspect --jsonl --max-records 100 -f documents.jsonl > reports.jsonl
stegdetect --inspect --contextual --jsonl --explain - < documents.jsonl > reports.jsonl
```

The CLI caps each input line at 4 MiB and each report at 16 MiB. It also
stops after 1,000 records by default and caps aggregate read bytes and
emitted JSON at 64 MiB each. `--max-records` may lower or raise the record
count, but the byte caps remain. An overlong line or aggregate limit stops
the batch with exit 4. Malformed JSON and non-string records yield held
reports; processing continues so callers can inspect every bounded record.
An empty batch exits 4 without a report.
The aggregate exit is 4 if any failure/limit occurred, 3 if any review/block
occurred, and 0 only when all processed records are allowed. Wait for the
final exit status before authorizing an *entire* batch. A partial output file
is not a whole-batch approval.

## RAG and tool-result boundaries

[`rag_gate.py`](../examples/rag_gate.py) inspects every retrieved document
before assembling a prompt. It holds the whole set if any document is held
or a trusted document/prompt cap is exceeded. Application-owned source IDs
remain outside the model prompt. [`tool_result_gate.py`](../examples/tool_result_gate.py)
inspects the tool's text immediately before the next model call. Tests use a
recorder in place of a model and assert it is never called on a held or
invalid input, while an allowed candidate is forwarded exactly.

```python
from examples.rag_gate import answer_with_documents
from examples.tool_result_gate import continue_with_tool_result

rag = answer_with_documents(question, [(trusted_id, retrieved_text)], model_call)
tool = continue_with_tool_result(tool_text, model_call)
```

These examples are framework-independent repository examples, not an installed
integration package. They test the final call boundary but do not establish
that the model obeys the caller, that retrieval/extraction is safe, or that a
document is authorized for the user. Keep model permissions, source allowlists,
and application authorization separate from document text. A real deployment
must test its own final model-call boundary and decide how to handle review.

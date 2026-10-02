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
human sentence to stderr, with no untrusted text or raw bidi controls. For
example, a direction override yields a `block` report on stdout and a static
"An explicit direction override can change displayed order" explanation on
stderr. The explanation describes Unicode evidence, not the author's intent.
Exit 0 means a complete allow with a forwarding candidate; 3 means a complete
review/block; 4 means invalid input, a limit, or scan/I/O failure; argparse
uses 2 for usage errors. The legacy CLI mode and its exit codes are unchanged.
The JSON includes counts and original Python-codepoint offsets. Do not render
input-derived fields raw in a terminal or HTML page.

## Document batches

`--jsonl` accepts one UTF-8 JSON **string** per line from stdin or `-f FILE`.
Each output line is the corresponding inspection report in the same order.
Input documents cannot supply a policy or a trusted source ID. Keep IDs in
your application and associate them by record order after the CLI completes.
For example, `documents.jsonl` can contain:

```jsonl
"ordinary retrieved text"
"text with a control\u202e"
```

The first report is an allow; the second is a block under the default policy.
Each report has `status`, `action`, `reason_codes`, and `candidate_text`.
Forward a candidate only when its report is complete and allowed, and only
after the process exits successfully if the whole batch must be accepted.

```bash
stegdetect --inspect --jsonl --max-records 100 -f documents.jsonl > reports.jsonl
stegdetect --inspect --contextual --jsonl --explain - < documents.jsonl > reports.jsonl
```

PowerShell can use the file form and check the exit code immediately:

```powershell
stegdetect --inspect --jsonl --explain -f documents.jsonl
if ($LASTEXITCODE -ne 0) { throw "Document batch was held or incomplete" }
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
The Bash command using `<` reads stdin; PowerShell users can use
`-f` as shown. Preserve the original input order alongside trusted source IDs,
and verify the number of reports before pairing them with those IDs.

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
integration package. The local tests exercise their final call boundary, and
the release validator loads both examples outside the checkout with an
isolated installed wheel and repeats six allow/hold/cap checks. They do not
establish that the model obeys the caller, that retrieval/extraction is safe,
or that a document is authorized for the user. Keep model permissions, source
allowlists, and application authorization separate from document text. A real deployment
must test its own final model-call boundary and decide how to handle review.
Inspect the exact untrusted text to be forwarded; if extraction, chunking, or
normalization changes it after inspection, inspect that changed text again.

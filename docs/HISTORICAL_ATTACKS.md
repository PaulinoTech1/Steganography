# Historical attacks vs stegdetect: 1-to-1 mapping

`stegdetect` is a **Unicode-carrier pre-filter**: it catches the *hiding*
layer of a prompt injection (invisible characters, display-order lies,
look-alike substitution), not the *instruction* layer (the words
themselves). This document maps documented historical attacks 1-to-1
against that capability: each attack's carrier, run through the
detector, with an honest verdict. Research compiled 2026-10-01; sources
at the bottom.

## Attacks this tool defeats

Each row: the historical carrier, the rule that fires, and the test
that reconstructs it. All reconstructions are `malicious` verdicts.

| Historical instance | Date | Carrier | stegdetect rule | Reconstruction test |
|---|---|---|---|---|
| Trojan Source (Boucher & Anderson, CVE-2021-42574) | Sep 2021 | Bidi overrides reorder displayed vs parsed text | `BIDI_OVERRIDE` (high) | `test_trojan_source_bidi_comment` |
| ASCII smuggling, Goodside publicizes tag block | Jan 2024 | Tag chars U+E0000–U+E007F mirror ASCII invisibly | `TAG_CHARACTER` (high) | `test_ascii_smuggling_tag_block` |
| Rehberger's ASCII Smuggler vs ChatGPT/Claude/Copilot | Jan–Aug 2024 | Same tag block; hidden instructions invoke tools | `TAG_CHARACTER` (high) | `test_ascii_smuggling_tag_block` |
| Trendyol vs Meta Llama Firewall | May 2025 | "ignore all previous instructions" camouflaged with zero-width spaces; passed Llama Firewall with zero-threat score | `ZERO_WIDTH` cluster (high) | `test_trendyol_llama_firewall_evasion` |
| meta-llama/llama#1382 filter-evasion claim | 2025 | Cyrillic homoglyphs + zero-width space + RLO combined | `MIXED_SCRIPT` + `ZERO_WIDTH` + `BIDI_OVERRIDE` | `test_llama_issue_1382_combo` |
| FireTail "Ghosts in the Machine" vs Gemini/Grok/DeepSeek | Oct 2025 | Tag-block instructions in calendar invites/emails; Google declined to fix | `TAG_CHARACTER` (high) | `test_ascii_smuggling_tag_block` |

Context: Hackett et al. (LLMSEC 2025) measured character-injection
evasion against six deployed guardrails and found tag smuggling
succeeding ~90%, bidi ~79%, zero-width/homoglyphs 44–76%. Several
vendors (ChatGPT, Copilot, Claude) now scrub tag characters server-side;
this tool implements that same scrubbing for anyone's pipeline.

## Attacks this tool does NOT defeat (honest boundary)

These are real, documented attacks whose carriers sit outside the
Unicode layer. Two boundary tests pin this so the tool is never
oversold: `test_plain_text_injection_is_out_of_scope` and
`test_rendering_trick_without_unicode_carrier_is_out_of_scope`.

| Historical instance | Date | Carrier | Why out of scope |
|---|---|---|---|
| Classic "ignore previous instructions" (Goodside/Willison) | Sep 2022 | Plain visible text | No carrier to detect; needs semantic analysis |
| Bing Chat "Sydney" jailbreak (Kevin Liu) | Feb 2023 | Plain visible text, direct conversation | Same as above |
| Indirect Prompt Injection (Greshake et al.) | Feb 2023 | Plain text in retrieved data | The stealth was positional (data/instruction collapse), not visual |
| Slack AI exfiltration (PromptArmor) | Aug 2024 | Plain text in public channel; exfil via Markdown link | Same as above |
| EchoLeak / CVE-2025-32711 (Aim Labs, M365 Copilot) | Jun 2025 | Plain text in markdown-formatted email; stealth via RAG retrieval | Same as above |
| Resume "white fonting" vs AI screeners (wild, ~1% of 196k resumes) | 2024–2025 | White-on-white text, microscopic fonts, hidden PDF layers | Rendering trick: at the Unicode layer the text is plain |
| Hidden "give a positive review" prompts in arXiv preprints (wild, 17–18 papers) | Jul 2025 | White text, microscopic fonts in PDF text layer | Same as above |
| WIPI web indirect injection | Feb 2024 | 0.0001px fonts, background-colored text, opacity 0, off-screen layout | Same as above |
| Google Threat Intel wild IPI scan (+32% malicious IPI) | Apr 2026 | Pixel-sized text, color-drained content, HTML metadata, invisible comments | Same as above |

Two accuracy notes from the research: EchoLeak is frequently mislabeled
as a "hidden" attack, but its payload was plain markdown email text.
And the wild resume data is mostly hidden *qualifications* (>90%), not
hidden instructions.

## What would be needed for the rest

- **Semantic layer (planned layer two):** plain-text injections
  (Sydney, EchoLeak, Slack AI, classic direct injection). Statistical /
  model-based analysis, per the README's roadmap.
- **Render/DOM-aware layer:** white text, 0px fonts, `display:none`,
  HTML comments, PDF layer tricks. Requires rendering the document, not
  just reading its characters.

## Sources

- Trojan Source: https://trojansource.codes/ (Boucher & Anderson, 2021)
- ASCII smuggling: https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/ (Goodside/Rehberger, Jan 2024)
- Claude ASCII smuggling: https://embracethered.com/blog/posts/2024/claude-hidden-prompt-injection-ascii-smuggling/
- FireTail "Ghosts in the Machine": https://www.firetail.ai/blog/ghosts-in-the-machine-ascii-smuggling-across-various-llms (Oct 2025)
- Trendyol vs Llama Firewall: https://cybersecuritynews.com/metas-llama-firewall/ (May 2025)
- meta-llama/llama#1382: https://github.com/meta-llama/llama/issues/1382
- Hackett et al., LLMSEC 2025: https://arxiv.org/abs/2504.11168
- Indirect Prompt Injection: https://arxiv.org/abs/2302.12173 (Greshake et al., Feb 2023)
- EchoLeak: https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html (Jun 2025)
- Slack AI: https://Simonwillison.net/2024/Aug/20/data-exfiltration-from-slack-ai/ (Aug 2024)
- Bing Sydney: https://www.techspot.com/news/97590-microsoft-bing-chatbot-ai-susceptible-several-types-prompt.html (Feb 2023)
- Hidden resume prompts: https://www.inc.com/deepali-vyas/the-invisible-font-resume-hack-is-breaking-ai-job-screeners-as-a-recruiter-i-dont-blame-candidates/91394378 (2024)
- Hidden arXiv review prompts: https://www.theregister.com/software/2025/07/07/scholars-sneaking-phrases-into-papers-to-fool-ai-reviewers/708598 (Jul 2025)
- WIPI: https://arxiv.org/abs/2402.16965 (Feb 2024)
- Google wild IPI measurement: https://blog.google/security/prompt-injections-web/ (Apr 2026)

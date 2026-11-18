# Legacy artifact histories

These JSONL files were produced by the actual `PublicArtifactStore.record` at
Core base commit `6142defb3de7cef44887c1685e4f670072585785`, loaded from a
`git archive` into a disposable directory. Each uses program `program`, producer
`public-artifacts`, account `owner`, kind `post`, public visibility, and URL
`https://example.test/posts/42`, with the suffixes below. IDs and timestamps are
the original generated values, not handcrafted events.

- `public_pending.jsonl`: created → cleanup_pending.
- `public_deleted.jsonl`: created → deleted.
- `query_created.jsonl`: created with `?view=thread`.
- `query_pending.jsonl`: created → cleanup_pending with the synthetic
  `?share=EXAMPLE_PRIVATE_VALUE` value. This value is deliberately fake; it
  demonstrates that the baseline could retain an unrecognized sensitive query.

The candidate tests copy these immutable fixtures into disposable storage; they
never operate on real artifact histories.

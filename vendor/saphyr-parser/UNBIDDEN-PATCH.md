# unbidden's patch to saphyr-parser 0.1.0

This is saphyr-parser 0.1.0 as published on crates.io, with one change to
`src/scanner.rs`. Cargo.toml's `[patch.crates-io]` points here. Drop the copy
and the patch entry once a release carries the fix upstream.

## The bug

An implicit single-pair mapping inside a flow sequence ends at the first `,`
of any flow mapping nested in its value:

```yaml
[k: {a: b, c: d}]
```

is read as `[{k: {a: b}, {c: d}: null}]`: the inner mapping is closed after
`a: b` and the rest becomes a second, mapping-valued key. It should be
`[{k: {a: b, c: d}}]`, which is what PyYAML, libyaml and the YAML 1.2 spec
give. No error is raised, so the misreading is silent.

The scanner keeps `implicit_flow_mapping_states` with one entry per open
flow *sequence* and a single `flow_mapping_started` flag for flow mappings.
Inside `{}` nested in `[k: ...]`, the last entry on the stack is the outer
sequence's `Inside`, so `fetch_flow_entry` ends that mapping at the inner `,`.
The flag is also never cleared when the `}` closes, so a later `k: v` in the
same sequence was not recognised as an implicit mapping.

## The fix

One stack entry per flow level: `{` pushes a new `NotApplicable` state, every
closing bracket pops, and `fetch_value` starts an implicit mapping only when
the innermost level is a sequence. `{` no longer sets `flow_mapping_started`,
which remains for the explicit `?` key.

Upstream's own tests pass with the change (the whole saphyr workspace, 642
tests including yaml-test-suite, at commit f32f385), and unbidden's YAML
reader agrees with PyYAML's `safe_load` on 30,000 generated documents
weighted towards nested flow collections, where before it did not.

## The diff

```diff
393a394,399
>     /// The level is a flow mapping (`{`), where a `:` is an ordinary key's and no implicit
>     /// mapping can start. Kept so that the stack has one entry per flow level and a `,` or `:`
>     /// inside `{}` is never taken for one belonging to an enclosing `[]`.
>     ///
>     /// unbidden patch: see vendor/saphyr-parser/UNBIDDEN-PATCH.md.
>     NotApplicable,
1473c1479,1480
<             self.flow_mapping_started = true;
---
>             self.implicit_flow_mapping_states
>                 .push(ImplicitMappingState::NotApplicable);
1499,1500d1505
<             // We are out exiting the flow sequence, nesting goes down 1 level.
<             self.implicit_flow_mapping_states.pop();
1501a1507,1508
>         // We are exiting the flow collection, nesting goes down 1 level.
>         self.implicit_flow_mapping_states.pop();
2489,2490c2496,2499
<         let is_implicit_flow_mapping =
<             !self.implicit_flow_mapping_states.is_empty() && !self.flow_mapping_started;
---
>         let is_implicit_flow_mapping = matches!(
>             self.implicit_flow_mapping_states.last(),
>             Some(ImplicitMappingState::Possible | ImplicitMappingState::Inside)
>         ) && !self.flow_mapping_started;
```

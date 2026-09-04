[English](README.md) | [Русский](README.ru.md)

# OpenShield TUI locale resources

The TUI embeds every supported JSON resource at compile time. It never derives
a resource path from locale input and never reads translation files at runtime.
A selected non-English locale is loaded as its complete map: there is no
per-message merge with, or fallback to, English.

## Supported locales

The current set has 31 locales. Every resource must contain the same complete
message key set as `en.json`; the tests derive the expected count from that
file so this documentation cannot silently become stale when UI text changes.

| Code | Language | Code | Language |
| --- | --- | --- | --- |
| `en` | English | `ru` | Russian |
| `zh` | Chinese | `es` | Spanish |
| `hi` | Hindi | `ar` | Arabic |
| `pt` | Portuguese | `fr` | French |
| `de` | German | `ja` | Japanese |
| `ko` | Korean | `id` | Indonesian |
| `tr` | Turkish | `it` | Italian |
| `pl` | Polish | `uk` | Ukrainian |
| `nl` | Dutch | `vi` | Vietnamese |
| `th` | Thai | `fa` | Persian |
| `be` | Belarusian | `az` | Azerbaijani |
| `kk` | Kazakh | `uz` | Uzbek |
| `tt` | Tatar | `ba` | Bashkir |
| `cv` | Chuvash | `ce` | Chechen |
| `sah` | Sakha (Yakut) | `tyv` | Tuvan |
| `krc` | Karachay-Balkar | — | — |

This is a best-effort set, not an exhaustive list of the languages spoken by
the peoples of Russia. Key completeness and format safety are machine-checked.
The newly added low-resource translations have not yet received comprehensive
review by native technical translators; such review is required before making
strong claims about idiomatic or terminological quality.
No native technical review is currently recorded for any of the 11 additions
from `be` onward listed in the lower part of the table.

## Translation gap inventory

These requested locale identifiers are not exposed yet because a complete,
technically meaningful translation could not be reviewed with
sufficient confidence: `hy` (Armenian), `ka` (Georgian), `ky` (Kyrgyz), `tg`
(Tajik), `mn` (Mongolian), `kbd` (Kabardian), `nog` (Nogai), `lbe` (Lak),
`tab` (Tabasaran), `ab` (Abkhaz), `abq` (Abaza), and `agx` (Aghul).

The fallback audit also removed these previously proposed resources: `udm`
(Udmurt), `kv` (Komi-Zyrian), `krl` (Karelian), `mhr` (Meadow Mari), `mrj`
(Hill Mari), `myv` (Erzya), `mdf` (Moksha), `alt` (Southern Altai), `av`
(Avar), `dar` (Dargwa), `lez` (Lezgin), and `kum` (Kumyk). Between 29 and
119 of their former 183 messages were copied verbatim from Russian, so presenting
them as complete translations would be misleading.

A subsequent all-pairs forensic audit quarantined `os` (Ossetian), `inh`
(Ingush), `bua` (Buryat), `xal` (Kalmyk), `ady` (Adyghe), and `kjh` (Khakas).
It found 161 identical values between `os` and `inh`, 156 between `bua` and
`xal`, 87 between `ady` and `krc`, and 61 between `kjh` and `kk`. The longest
contiguous copied blocks contained 139 and 126 messages. These patterns are
not explained by shared protocol names or short technical labels. The six
resources remain unsupported pending replacement and native technical review.

Substituting Russian or a related language mislabels the interface. All codes
in this inventory remain unsupported until a native technical reviewer
supplies or approves a complete resource.

## Enforced invariants

- Every resource has exactly the same keys as `en.json`.
- Placeholder sets such as `{error}` and `{revision}` must match English.
- No non-English message value may be exactly equal to its English value.
- Every unordered locale pair is checked for exact shared values. After
  placeholders and common protocol/product identifiers are excluded, a pair
  may share at most 24 nontrivial messages in total and at most four substantive
  messages (four or more words and at least 20 letters). This permits common
  technical labels while detecting bulk copying from any language; it does not
  certify linguistic quality.
- Ordinary UI prose is translated. Product names, socket names, keyboard keys,
  protocol names, and identifiers remain unchanged where translation would be
  incorrect.
- Observation text states the actual access boundary: only `root` or a member
  of the `openshield` group can observe; mutations require `root`.
- Counter text is backend-neutral and refers to firewall counters, not to one
  particular implementation.
- Embedded resources remain bounded by the limits in `i18n.rs`; control and
  bidirectional-override characters are rejected. The Persian zero-width
  non-joiner remains allowed because it is an orthographic character.
- A single alphabetic token may not mix Latin and Cyrillic code points. This
  prevents confusable-script substitutions while still allowing separate
  technical identifiers such as `IPC-сокет`.

Explicit `--locale` values are validated as bounded ASCII POSIX-style locale
identifiers. Unknown explicit locales are rejected. Automatic detection uses
`LC_ALL`, `LC_MESSAGES`, `LANGUAGE`, then `LANG`; unsupported candidates fall
through to the next candidate and ultimately to English.

## Updating translations

Update `en.json` first, add the same key to every other JSON file, preserve all
placeholders, and then run:

```console
cargo test -p openshield-tui --locked
cargo clippy -p openshield-tui --all-targets -- -D warnings
```

Native-speaker review should check security terminology, directionality,
keyboard alignment, and the distinction between a serialized policy snapshot
and an image or screenshot.

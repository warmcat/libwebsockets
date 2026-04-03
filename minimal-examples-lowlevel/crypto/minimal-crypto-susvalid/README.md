# lws-crypto-susvalid

This is a developer tool that scans a given file for suspicious Unicode characters commonly associated with invisible payloads, such as zero-width formatters, bidirectional overrides, and invisible language tags.

Text encodings involving these characters are often utilized for Trojan Source attacks, acting as hidden payloads or text obfuscators that might be inadvertently executed or evaluated.

## Usage

```bash
$ lws-crypto-susvalid <file>
```

The tool will seamlessly evaluate raw streams, including valid UTF-8 and Quoted-Printable payloads. It will decode soft line breaks and quoted representation correctly so that maliciously fragmented invisible blocks will still be recognized.

When an offending Unicode character sequence appears, the tool prints its hexadecimal scalar value along with the file coordinates (line, column, and raw byte position):

```bash
[2026/04/03 16:24:26:6147] N: Suspicious Unicode U+202E found at byte 19 (line 2, col 4)
```

**Note:** The tool handles security explicitly by preventing these suspicious characters from being directly emitted to your terminal. It logs only the harmless `U+XXXX` scalar hex values.

## Detected ranges

1. **`U+200B` - `U+200F`:** Zero Width spaces and formatting markers (e.g. LRM, RLM).
2. **`U+202A` - `U+202E`:** Bidi overrides (e.g. LRE, RLO, etc).
3. **`U+2060` - `U+2069`:** Isolate controls and word joiners.
4. **`U+FE00` - `U+FE0F` / `U+E0100` - `U+E01EF`:** Variation Selectors.
5. **`U+E0000` - `U+E007F`:** Tags Block.
6. **Isolated targets:** Hangul Fillers (`U+3164`), Half-width Hangul Fillers (`U+FFA0`), BOMs (`U+FEFF`), Mongolian Vowel Separators (`U+180E`).

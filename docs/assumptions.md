# Assumptions about pcapng specs

Because this parser is not a general purpose parser, there's assumptions made to keep the focus on
performance.

### The given pcapng file must :

- Not malformed. The parser would just return -1 on any kind of malform,(e.g, file doesn't starts with section header block) instead of any recovery/resync logic.
- Only little endian is supported for metadata.

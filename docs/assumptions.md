# Assumptions about pcapng specs

Because this parser is not a general purpose parser, there's assumptions made to keep the focus on
performance.

### The given pcapng file must :

- Not malformed
- Contain only 1 interface
- Little endian pcapng metadata. Packets are not parsed and not included by this line.

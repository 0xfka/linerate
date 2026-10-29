# Design notes

This project aims to replay pcapng captures fast enough to saturate a 10/25 GbE
port. Input restrictions are documented in [assumptions.md](assumptions.md).
These notes describe the current direction on a early development phase, not measured performance guarantees.

## Fetching the pcapng from disk : Double-mapped buffer and io_uring

For fetching the file from NVMe to RAM, O_DIRECT, io_uring with SQ polling is used. Polling on another core allows us to prevent switching to kernel space, because the logic that decides to fetch more of the pcapng file will be in the same core which does all the pcapng parsing work and managing DPDK state.

Temporarily, the buffer is 1 GiB physical RAM with 2 GiB of virtual memory space. The trick is basically mapping the 2 continious memory space to the same
physical RAM, which allows us to continue from the start if we pass the size.
For example, with a 64-byte backing buffer (addresses are representative):

```text
Virtual memory: two adjacent mappings

       0                    63 64                   127
       +----------------------+----------------------+
       |    first mapping     |    second mapping    |
       +----------------------+----------------------+
                  |                      |
                  +-----------+----------+
                              |
                              v
                   +----------------------+
                   | same backing storage |
                   +----------------------+
                   0                     63

Crossing the virtual boundary:
    Virtual address:   62 --> 63 --> 64 --> 65
    Backing offset:    62 --> 63 -->  0 -->  1
```

Inside GDB, it can be checked via writing to any mapping and checking the other.
This trick is preventing checking the size at every iter natively.
The memfd allows us to use the same physical memory with 2 virtual mapping, since they both point to the same fd. The capacity is currently 1 GiB as a dummy value and aimed to be reduced.

## Kernel bypass networking

The kernel bypass networking framework will probably be DPDK. I don't use my own 82599 PMD implementation to be able to benchmark the code on different NIC's easily.

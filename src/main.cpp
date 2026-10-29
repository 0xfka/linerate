#include <errno.h>
#include <fcntl.h>
#include <liburing.h> // TODO: we really need 2 of io_uring libs ?
#include <liburing/io_uring.h>
#include <linux/memfd.h>
#include <span>
#include <stdio.h> // fopen syscall
#include <string.h>
#include <sys/mman.h> // hugepages
#include <unistd.h>

#include "pcapng.hpp"
#include <cstdlib>

constexpr uint BLOCK_SZ = 128;
/* arg1 : pcapng path */
int main(int argc, char *argv[]) {
  // argv[0] is bin name already
  if (argc != 2) [[unlikely]] {
    return EINVAL;
  }
  const int fd = open(argv[1], O_DIRECT);
  if (fd == -1) [[unlikely]] {
    return errno;
  }
  constexpr std::size_t hugepage_sz = 1 << 30; // 1 GiB
  int memfd = memfd_create("inf", MFD_HUGETLB | MFD_HUGE_1GB);
  if (memfd == -1) {
    return errno;
  }
  void *virt =
      mmap(nullptr, 2 * hugepage_sz, PROT_NONE,
           MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB | MAP_HUGE_1GB, -1,
           0); // virtual memory address space
  if (virt == MAP_FAILED) {
    return errno;
  }

  void *mem =
      mmap(virt, hugepage_sz, PROT_READ | PROT_WRITE,
           MAP_FIXED | MAP_SHARED | MAP_POPULATE | MAP_HUGETLB | MAP_HUGE_1GB,
           memfd, 0);
  void *mem2 =
      mmap((uint8_t *)virt + hugepage_sz, hugepage_sz, PROT_READ | PROT_WRITE,
           MAP_FIXED | MAP_SHARED | MAP_POPULATE | MAP_HUGETLB | MAP_HUGE_1GB,
           memfd, 0);
  if (mem == MAP_FAILED | mem2 == MAP_FAILED) [[unlikely]] {
    return errno;
  }
  memset(mem, 0, hugepage_sz);
  std::uint8_t *p = reinterpret_cast<std::uint8_t *>(mem);
  const ulong file_sz = lseek(fd, 0, SEEK_END);
  if (file_sz == (ulong)-1)
    return errno;
  // map_populate should already preventing page faults..
  memset(p, 0, 1 << 30);
  struct io_uring_sqe *sqe;
  struct io_uring_cqe *cqe;
  struct io_uring_params conf;
  memset(&conf, 0, sizeof(io_uring_params));
  conf.flags = IORING_SETUP_SQPOLL /* Poll SQ instead of waiting for a syscall
                                       to pick up */
               | IORING_SETUP_SQ_AFF /* affinity */;
  conf.sq_thread_cpu = 1;
  conf.sq_thread_idle = 20000;
  struct io_uring ring;
  // TODO: some syscalls sets errno at err, some return the error code itself ?
  // Maybe standardize somehow, such as, a TEST() macro ?
  int err = io_uring_queue_init_params(BLOCK_SZ, &ring, &conf);
  if (err != 0) [[unlikely]] {
    return -err;
  }
  if (io_uring_register_files(&ring, &fd, 1) != 0) [[unlikely]] {
    return errno;
  }
  sqe = io_uring_get_sqe(&ring);
  // TODO: Probably use registered buffers
  ulong read;
  std::uint32_t file_curr = 0;
  read = hugepage_sz + file_curr > file_sz ? file_sz - file_curr : hugepage_sz;
  io_uring_prep_read(sqe, 0, p, read, file_curr);
  file_curr += read;
  io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
  io_uring_submit(&ring);
  io_uring_wait_cqe(&ring, &cqe);
  SectionHeaderBlock *shb = (SectionHeaderBlock *)p;
  // block type is palindrome and at most, this check can only validate the file
  // looks like a pcapng file. This checks are probably unnecessary because the
  // parser will don't support malformed pcapng files.
  if (shb->block_type != e_shb_block_type) [[unlikely]] {
    return -1;
  }
  if (shb->byte_order_magic != e_byte_order_magic) [[unlikely]] {
    return -1; // Big endian not supported on parsing
  }
  p += shb->block_total_length;
  InterfaceDescriptionBlock *idb = (InterfaceDescriptionBlock *)p;
  // TODO: expect idb after fist shb. Is it %100 true ?
  if (idb->block_type != e_idb_block_type) [[unlikely]] {
    return -1;
  }
  /* Maybe provide telemetry with things like that ?
     We can read the values by fetching them with Shared state on another
     seperate core, it's only 1 cmp + 1 add for hot path. But, will use a
     register or cause a memory fetch?
  */
  std::uint32_t truncated_packet_count = 0;
  p += idb->block_total_length;
  /* TODO: According to specs, it looks like only enhanced packet block is used
     at pcapng ? "Packet Block (Appendix A): it contains a single captured
     packet, or a portion of it.  It is OBSOLETE, and superseded by the Enhanced
     Packet Block (Section 4.3)."
      - https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
      Maybe only support EPB for every packet block ?  */
  EnhancedPacketBlock *epb = (EnhancedPacketBlock *)p;
  if (epb->block_type != e_epb_block_type) [[unlikely]] {
    return -1;
  }
  /* Maybe provide telemetry with things like that ?
     We can read the values by fetching them with Shared state on another
     seperate core, it's only 1 cmp + 1 add for hot path. Because every epb has
     the required values, we don't need seperate registers ( etc, keeping the
     snap_len after idb)
  */
  epb->original_packet_length > epb->captured_packet_length
      ? ++truncated_packet_count
      : 0;
  std::span<std::uint8_t> firstpacket(
      p + sizeof(EnhancedPacketBlock),
      epb->captured_packet_length); // temp. for checking firstpacket from GDB
  return 0;
}

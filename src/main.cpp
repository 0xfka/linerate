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

#include "parser.hpp"
#include "pcapng.hpp"
#include <cstdlib>

constexpr uint BLOCK_SZ = 128;
/* arg1 : pcapng path */
int main(int argc, char *argv[]) {
  // argv[0] is bin name already
  if (argc != 2) [[unlikely]] {
    return EINVAL;
  }
  const int fd = open(argv[1], O_RDONLY | O_DIRECT);
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
  // IOPOLL polls which core will receive the CQ. Because the SQ is sent by
  // our polling core, this core also polls for IO.
  conf.flags =
      IORING_SETUP_SQPOLL /* Poll SQ instead of waiting for a syscall
                              to pick up */
      | IORING_SETUP_SQ_AFF /* affinity */ |
      IORING_SETUP_IOPOLL /* TODO(doc): Maybe document IOPOLL requirements, such
                             as filesystem. BTRFS was not supported and XFS is
                             used for the pcap file.*/
      ;
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
  struct iovec iovecs = {.iov_base = mem, .iov_len = hugepage_sz};
  err = io_uring_register_buffers(&ring, &iovecs, 1);
  if (err != 0) [[unlikely]] {
    return -err;
  }
  sqe = io_uring_get_sqe(&ring);
  ulong read;
  std::uint32_t file_curr = 0;
  read = hugepage_sz + file_curr > file_sz ? file_sz - file_curr : hugepage_sz;
  io_uring_prep_read_fixed(sqe, 0, mem, read, file_curr, 0);
  file_curr += read;
  io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
  io_uring_submit(&ring);
  err = io_uring_wait_cqe(&ring, &cqe);
  if (err != 0) [[unlikely]] {
    return err; // if not zero, res is invalid.
  }
  if (cqe->res < 0) [[unlikely]] {
    return -cqe->res;
  }
  std::array<std::span<const uint8_t>, 64> pkts;
  std::uint32_t truncated_pkt_cnt = 0;
  std::uint8_t idx_pkt = 0; //  batch idx, if 64, send to TX
  // is this generated a jump table ?
  HeaderBlockPrefix *&prefix = (HeaderBlockPrefix *&)p;
  switch (prefix->block_type) {
  case e_shb_block_type:
    p += prefix->block_total_length;
    break;
  case e_idb_block_type:
    p += prefix->block_total_length;
    break;
  case e_epb_block_type:
    std::uint8_t send = p_epb(p, pkts, truncated_pkt_cnt, idx_pkt);
    EnhancedPacketBlock *epb = (EnhancedPacketBlock *)p;
    p += epb->block_total_length;
    /* This check cannot be branchless because writing to TX of a NIC cannot
       safely execute. This path will only be true at every 64 packets, at the
       exact 64th iter. Leftover packets after all the pcapng is parsed can be
       handled at another check. This code should be easy to predict for the
       branch predictor after learned, there's no compiler hints that says
       "enter this branch every 64th time you saw it" as researched.
    */
    if (send == 1) {
      // Send the packets to TX
      idx_pkt = 0;
    }
    break;
  }
  return 0;
}

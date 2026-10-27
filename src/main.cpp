#include <errno.h>
#include <fcntl.h>
#include <liburing.h> // TODO: we really need 2 of io_uring libs ?
#include <liburing/io_uring.h>
#include <stdio.h> // fopen syscall
#include <string.h>
#include <sys/mman.h> // hugepages
#include <unistd.h>

#include "pcapng.hpp"
#include <cstdlib>

/*  CPU affinities and multi-core
 *  Targeted zen microarchitectures contains 8 core per core complex, so
 *  multi core can go up to 8 without cross CCX latencies.
 *  Multi threading is disabled to prevent CPU trashing and for this purpose,
 *  The sibling threads of given cores will be disabled.
 *  JOBS REQUIRING A SEPERATED CORE :
 *  1 ) The binary itself. Core 0
 *  2 ) Polling io_uring, this core will be set to sq_thread_cpu, core 1.
 *
 *  This part will be updated when other work requires a seperated core.
 *
 */
// io_uring parameters, currently placehodlers. NOT profiled.
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
  /* set hugepages
     This project will probably require GB's of hugepage,
     for prefetching at DRAM since fetching at NVMe at line rate of
     10G/25G would be impossible.
     TODO: This part needs to be documented */
  constexpr std::size_t hugepage_sz = 1 << 30; // 1 GiB
  void *mem =
      mmap(NULL, hugepage_sz, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_HUGE_1GB, -1, 0);
  if (mem == MAP_FAILED) [[unlikely]] {
    return errno;
  }
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
    // TODO: some syscalls returns errno at err, and some does -errno. Should we
    // do -errno when return to normalize or, something else like that ?
    return errno;
  }
  sqe = io_uring_get_sqe(&ring);
  [[maybe_unused]] std::uint32_t curr = 0;
  ulong valid = 0; // the biggest number that can be readed as p + valid
  /* Read 1 GiB if left, everything if not.
     Since the pcapng files we are going to use needs to be
     huge, 1 GiB selection may needs to be reconsidered again in the future.
    */
  // TODO: Probably use registered buffers
  ulong read;
  read = hugepage_sz + valid > file_sz ? file_sz - valid : hugepage_sz;
  io_uring_prep_read(sqe, 0, p, read, valid);
  valid += read;
  io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
  io_uring_submit(&ring);
  io_uring_wait_cqe(&ring, &cqe);
  SectionHeaderBlock *shb = (SectionHeaderBlock *)p;
  // TODO: block type is palindrome and it always passes if the file is a valid
  // pcapng
  if (shb->block_type != block_type_expected) [[unlikely]] {
    return -1;
  }
  if (shb->byte_order_magic != byte_order_magic_expected) [[unlikely]] {
    return -1; // Big endian not supported on parsing
  }
  return 0;
}

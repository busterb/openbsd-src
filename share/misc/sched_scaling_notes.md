# Multi-core scaling bottleneck analysis
## OpenBSD arm64 (CIX Sky1, 8x A720 + 4x A520), 2026-04-08

### Methodology

Profiled a parallel kernel build (ninja) across all scheduler configurations
using `kcpuflamegraph.bt` → `bspeedscope`, combined with wall-clock/CPU-time
data from `sched_bench.sh`.  Build saturates at j=8-9; user+sys time at
saturation is ~193s over ~27s real → ~7.2 effective cores out of 12.
System time (~94s) is nearly equal to user time (~99s), indicating ~49% of
all CPU time spent in the kernel.

### Hotspot summary (active CPUs 0,1,6-11; ~31k samples)

| Function                  | Inclusive % | Notes                                    |
|---------------------------|-------------|------------------------------------------|
| udata_abort / uvm_fault   | 28%         | Page faults from fork/exec COW + demand  |
| cpu_tlb_flush_asid        | 11%         | TLB invalidation after pmap changes      |
| svc_handler               | 20%         | exit(30%), mprotect(22%), openat(10%) …  |
| exit1                     | 6%          | Short-lived compiler process cleanup     |
| mtx_enter                 | 5%          | pmap/UVM page queue lock contention      |

CPUs 2-5 (A520 L-cores) show 99-100% idle (proc_trampoline), confirming
capacity-ordered scheduling is keeping them clear of normal work.

CPU 0 shows 69% handle_el0_sync vs ~49% on all other active cores, consistent
with it absorbing disproportionate interrupt/syscall traffic as primary CPU.

### Why scaling plateaus at j=8

**TLB broadcast stalls.**  `cpu_tlb_flush_asid` is called from six paths
simultaneously: page fault fixup (udata_abort 29%, uvm_fault_lower 14%,
uvm_fault_upper 13%), pmap_enter (12%), pmap_protect (13%), and uvm_map_protect
(11%).  On arm64, `TLBI ASIDE1IS` is a broadcast instruction: the issuing CPU
stalls until all peer CPUs acknowledge completion.  With 8+ concurrent processes
each faulting and mprotect-ing, these broadcasts become a full-system
serialisation point.

**pmap/UVM lock contention.**  Top callers of mtx_enter are all UVM/pmap:
uvm_pageactivate (34%), pmap_remove_pted (15%), pmap_enter (8%),
uvm_pmr_freepages (8%), vm_map_lock_ln (4%).  The global page queue lock
(uvm_lock_pageq) serialises page activation across all cores.

**mprotect rate.**  mprotect is 22% of all syscalls — compilers do
mmap(RW)+write+mprotect(RX) for each shared library loaded at exec time.
Each call drives pmap_protect → cpu_tlb_flush_asid → broadcast stall.
A typical compiler exec fires 10-20 mprotects before main() is reached.

---

## Planned experiments

### 1. Deferred / batched TLB invalidation in pmap

**Hypothesis:** Flushing the TLB inline on every pmap_protect / pmap_enter
broadcasts a barrier to all CPUs for each individual page.  Accumulating
pending TLB work per-CPU and flushing once on syscall return or at a natural
quiescent point should reduce the number of broadcast stalls proportionally
to the number of pages modified per syscall.

**Prior art:** OpenBSD already has `pmap_tlb_shootdown()` infrastructure on
some architectures; check whether arm64 uses deferred shootdown on all pmap
paths or only some.  Linux uses `mmu_gather` for batched TLB teardown.

**Experiment steps:**
- Instrument `cpu_tlb_flush_asid` with a counter kprobe to measure call rate
  before and after any change (btrace script: `kprobe:cpu_tlb_flush_asid`).
- Identify which pmap paths on arm64 flush inline vs. via shootdown and why.
- Try deferring flushes in `pmap_protect` to syscall return for the mprotect
  path (lowest risk, highest frequency).
- Re-run `sched_bench.sh` and compare saturation point and system time.

**Risk:** Deferred flushes require careful ordering guarantees.  A CPU must
not execute with stale TLB entries between the pmap modification and the
deferred flush.  Needs thorough review and stress testing (fsx, regress).

---

### 2. Page queue lock pressure (uvm_pageactivate)

**Hypothesis:** `uvm_pageactivate` is the single hottest mutex site (34% of
all mtx_enter samples), called on every page fault to move pages from the
inactive to the active queue.  A global lock for this queue serialises all
concurrent faults across all CPUs.

**Prior art:** FreeBSD sharded its page queues per-CPU/NUMA domain (r287474,
r312899).  NetBSD uses a similar per-CPU active list approach.  OpenBSD
currently has a single global `uvm_lock_pageq`.

**Experiment steps:**
- Use `kprobe:uvm_pageactivate` with `tid` correlation to measure lock hold
  time and contention rate under parallel build load.
- Profile lock wait time: `kprobe:mtx_enter { @wait[kstack] = hist(nsecs); }`
  filtered to stacks containing `uvm_pageactivate`.
- Prototype: skip activation (leave page on inactive queue) when the fault
  is a transient exec-time mapping (detected by refcount or short vm_object
  lifetime).  This avoids the lock entirely for pages that will be freed soon.
- Alternatively: batch activation — accumulate a per-CPU list of pages to
  activate and flush to the queue under one lock acquisition.
- Re-run benchmark.

**Risk:** Changing page queue accounting affects reclaim heuristics.  A page
left on the inactive queue too long may be reclaimed under memory pressure.
Needs testing under both low-memory and high-parallelism conditions.

---

### 3. mprotect rate reduction (W^X at exec time)

**Hypothesis:** The linker and dynamic linker call mprotect ~10-20 times per
exec to enforce W^X (map RW, write relocations, mprotect RX).  At 22% of all
syscalls during a parallel build this is a significant source of both syscall
overhead and TLB broadcast stalls.  Reducing the number of distinct mprotect
calls per exec would directly reduce TLB flush rate.

**Prior art:** GNU_RELRO + BIND_NOW (`-z relro -z now`) causes the dynamic
linker to do one bulk mprotect at startup instead of per-library.  OpenBSD's
ld.so already supports these but the default toolchain build flags may not
use them everywhere.  `mprotect` merging in the kernel (`uvm_map_protect`
coalescing adjacent same-permission regions) is another angle.

**Experiment steps:**
- Confirm the mprotect call sites: `kprobe:sys_mprotect { @[ustack] = count(); }`
  on a build process to see whether calls originate from ld.so, libc, or
  generated code.
- Count mprotects per exec: `kprobe:sys_mprotect { @[pid, comm] = count(); }`
  during a single compiler invocation.
- Test building the ports tree with `-Wl,-z,now` and measure mprotect rate
  reduction and wall-clock impact.
- Investigate whether `uvm_map_protect` can coalesce adjacent mprotect calls
  on the same vm_map before calling `pmap_protect`, reducing TLB flushes even
  without changing userland.

**Risk:** `-z now` increases startup time (all relocations resolved eagerly)
and breaks lazy binding, which some software relies on.  Should be profiled
separately to confirm the tradeoff is worthwhile for build workloads.

**Attempted: local-only TLB flush when pm_active == 1 (REVERTED)**

Tried replacing `tlbi aside1is` (broadcast) with `tlbi aside1` (local) in
`pmap_protect` when `pm_active == 1`.  Caused random SIGILL crashes during
linking.

Root cause: `pmap_deactivate` switches TTBR0 away but does NOT flush TLBs.
ARM64 TLB entries survive context switches tagged by ASID.  `pm_active` counts
CPUs that currently have TTBR0 pointing at the pmap, not CPUs that have live
TLB entries.  A process previously scheduled on CPU Y leaves cached entries
there; local flush on CPU X misses them; if the process later runs on CPU Y
with the same ASID it executes with stale (RW) PTEs after an RX mprotect.

To do this safely would require either a per-CPU bitmask on the pmap tracking
which CPUs have had entries loaded since the last broadcast flush (FreeBSD's
approach), or flushing TLBs in `pmap_deactivate` on switch-out (expensive).

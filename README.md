# NVIDIA HPC Benchmarks for an AI Cluster with 64 H200 GPUs (8 nodes x 8 GPUs)
## Benchmarks Included

| # | Benchmark | What It Measures                     | Run Time   |
|---|-----------|--------------------------------------|------------|
| 1 | STREAM    | Per-GPU HBM3e memory bandwidth       | ~2 min     |
| 2 | HPCG      | Sparse linear algebra + memory       | ~10 min    |
| 3 | HPL       | Dense FP64 FLOPS + fabric scaling    | ~30-60 min |
| 4 | HPL-MxP   | Tensor Core mixed-precision peak     | ~20-40 min |

**Recommended run order:** STREAM → HPCG → HPL → HPL-MxP
(Start simple to validate per-GPU health, then scale up to full cluster.)

---

## Phase 0: Pull and Convert the NGC Container

The NVIDIA HPC Benchmarks ship as a single NGC container. We convert it to
an Apptainer SIF for use under Slurm.

```bash
# On a node with internet access (or via proxy), pull the container.
# Latest tag as of early 2026 is 25.09.  Check NGC for newer tags:
#   https://catalog.ngc.nvidia.com/orgs/nvidia/containers/hpc-benchmarks

# Set your destination (PowerScale shared storage recommended)
export SIF_DIR=/home/ascensus/containers
mkdir -p ${SIF_DIR}

# Pull and convert — this downloads ~15-20 GB
apptainer pull ${SIF_DIR}/hpc-benchmarks-25.09.sif \
    docker://nvcr.io/nvidia/hpc-benchmarks:25.09

# Verify
ls -lh ${SIF_DIR}/hpc-benchmarks-25.09.sif
```

> **Note:** If your nodes cannot reach NGC directly, pull via Podman on a
> connected host and then convert:
> ```bash
> podman pull nvcr.io/nvidia/hpc-benchmarks:25.09
> podman save nvcr.io/nvidia/hpc-benchmarks:25.09 -o hpc-bench-25.09.tar
> # Transfer tar to cluster, then:
> apptainer build ${SIF_DIR}/hpc-benchmarks-25.09.sif \
>     docker-archive:hpc-bench-25.09.tar
> ```

**After pulling, verify the internal layout:**
```bash
apptainer exec --nv ${SIF_DIR}/hpc-benchmarks-25.09.sif ls /workspace/cuda12/
# You should see: hpl.sh  hpl-mxp.sh  hpcg.sh  stream-gpu-test.sh  ...
# If the cuda12/ subdirectory does not exist, the scripts may be at
# /workspace/hpl.sh etc. — adjust all script paths accordingly.
```

**InfiniBand note:** All Slurm scripts include `--bind /run,/var` in the
Apptainer exec call. This is needed for InfiniBand verbs access (the IB
device nodes under `/dev/infiniband/` are exposed by `--nv`, but runtime
files in `/run` and `/var` are also needed). If you still see IB errors,
you may also need `--bind /etc/libibverbs.d` or `--bind /dev/infiniband`.

---

## Phase 1: STREAM (Per-GPU Memory Bandwidth)

**Purpose:** Confirm each H200's HBM3e is delivering close to 4.8 TB/s.
This is a sanity check — run on a single node first.

**Submit:**
```bash
sbatch 01-stream.sbatch
```

**Expected results (per GPU):**
- TRIAD: ~4,300,000 - 4,600,000 MB/s (FP64) — roughly 90-95% of peak 4.8 TB/s
- (STREAM reports bandwidth in MB/s; 4.8 TB/s = 4,800,000 MB/s)

---

## Phase 2: HPCG (Sparse Linear Algebra)

**Purpose:** Stress memory subsystem, data movement, and InfiniBand interconnect
with a workload pattern closer to real scientific applications.

**Submit (single node first, then full cluster):**
```bash
sbatch 02-hpcg-1node.sbatch    # Single-node validation
sbatch 02-hpcg-8node.sbatch    # Full 8-node run
```

**Expected results:**
- Single node (8 GPUs): ~4,000-5,000 GFLOP/s
- Full cluster (64 GPUs): should scale ~7-8× over single node

---

## Phase 3: HPL (Dense FP64 Linpack)

**Purpose:** Maximum sustained FP64 compute + full-cluster InfiniBand stress.
This is the TOP500 benchmark. It will expose GDR issues immediately —
if GPU Direct RDMA is not working, multi-node efficiency will crater.

**Submit (single node first, then full cluster):**
```bash
sbatch 03-hpl-1node.sbatch     # Single-node baseline
sbatch 03-hpl-8node.sbatch     # Full 8-node run (THE stress test)
```

**Expected results:**
- Single H200 GPU: ~42-50 TFLOPS (FP64)
- Single node (8 GPUs): ~320-380 TFLOPS
- Full cluster (64 GPUs): ~2,200-2,700 TFLOPS at >85% parallel efficiency

> **Key diagnostic:** Compare per-GPU GFLOPS at 1 node vs 8 nodes.
> If per-GPU drops >20%, suspect GDR / InfiniBand issues.

---

## Phase 4: HPL-MxP (Mixed-Precision Tensor Core Linpack)

**Purpose:** Exercise Tensor Cores in FP16 (or FP8) with iterative refinement
to FP64 accuracy. This shows the AI-relevant peak compute of the cluster.

**Submit:**
```bash
sbatch 04-hpl-mxp-1node.sbatch
sbatch 04-hpl-mxp-8node.sbatch
```

**Expected results:**
- Single node LU factorization: ~200-250 TFLOPS/GPU in FP16
- Full cluster: massive scaling with Tensor Core acceleration

---

## Tuning Notes

### CPU/Memory Affinity (XE9680)

The Dell XE9680 has 2 NUMA domains (socket 0 and socket 1). GPUs 0-3 are
typically on NUMA 0, GPUs 4-7 on NUMA 1. The affinity strings in the scripts
use the DGX-H100 pattern since the XE9680 HGX baseboard has the same topology:

```
--mem-affinity 0:0:0:0:1:1:1:1
--cpu-affinity 0-13:14-27:28-41:42-55:56-69:70-83:84-97:98-111
```

> **IMPORTANT:** You must verify your actual topology. SSH to a node and run:
> ```bash
> nvidia-smi topo -m
> numactl --hardware
> lscpu | grep "NUMA node"
> ```
> If your Xeon has a different core count than 112 total (56 per socket),
> adjust `--cpu-affinity` accordingly. For example, with 2×64-core Xeons
> (128 cores total), you'd use:
> ```
> --cpu-affinity 0-15:16-31:32-47:48-63:64-79:80-95:96-111:112-127
> ```

### HPL Matrix Size (N)

The matrix size N determines how much GPU memory is used. The formula is:

```
Memory per GPU (bytes) = 8 × N² / (P × Q)
```

where P×Q = total MPI ranks (= total GPUs). N should be a multiple of NB
for optimal performance, and you need to leave ~3 GB per GPU for the driver.

For H200 with 141 GB (usable ~138 GB), targeting ~80% utilization:
- 8 GPUs  (1 node):  N = 344064  (NB-aligned, uses ~110 GB/GPU = 78%)
- 64 GPUs (8 nodes): N = 972800  (NB-aligned, uses ~110 GB/GPU = 78%)

NB (block size) of 1024 is a safe default for Hopper architecture.

> **Tip:** If you want more aggressive memory use (~85%), try:
> - 1 node:  N = 358400  (~120 GB/GPU)
> - 8 nodes: N = 1013760 (~120 GB/GPU)
> Start conservative and increase N if runs succeed without OOM.

### HPL-MxP Matrix Size

HPL-MxP uses lower-precision arithmetic on the GPU (FP16 by default) and
stores the FP64 reference matrix on the host. The GPU memory footprint is
roughly 2 × N² / (P×Q) bytes for FP16, so N can be much larger than in HPL.
The host memory footprint is 8 × N² / (P×Q) bytes per rank, which must fit
in system RAM (XE9680 has ~2 TB, so ~256 GB per rank with 8 ranks/node).

Good starting points:
- 1 node (8 GPUs):  N = 485376, NB = 2048  (~55 GB FP16/GPU, ~219 GB FP64/host-rank)
- 8 nodes (64 GPUs): N = 901120, NB = 2048  (~24 GB FP16/GPU, ~95 GB FP64/host-rank)

All N values above are aligned to their respective NB (N mod NB == 0).
For the 1-node case, host RAM is the binding constraint — each of the 8
MPI ranks needs ~219 GB for the FP64 matrix, requiring ~1.75 TB total
out of the XE9680's 2 TB system RAM.

### InfiniBand / GDR Validation

Before running multi-node HPL, confirm GDR is working:

```bash
# On any two nodes, run a quick NCCL all_reduce test:
srun -N 2 --ntasks-per-node=8 --gres=gpu:8 \
    <path-to-nccl-tests>/all_reduce_perf -b 8 -e 8G -f 2 -g 1

# Expected bus bandwidth for 8-node NDR: ~350-370 GB/s
# If you see <100 GB/s, GDR is not active.
```

---

## Interpreting Results

### HPL Output
Look for the line:
```
WC00L2L2  <N>  <NB>  <P>  <Q>  <Time>  <GFLOPS>
```
The GFLOPS value is your Rmax (sustained peak).

### HPCG Output
Look for:
```
Final Summary::HPCG result is VALID ...
Final Summary::HPCG 2.4 rating ... = <GFLOP/s>
```

### STREAM Output
Look for TRIAD bandwidth — that's the canonical number.

### HPL-MxP Output
Look for both the overall GFLOPS and the LU factorization GFLOPS
(the latter shows pure Tensor Core throughput).

---

## File Inventory

```
01-stream.sbatch         — Single-node GPU STREAM benchmark
02-hpcg-1node.sbatch     — Single-node HPCG
02-hpcg-8node.sbatch     — Full-cluster HPCG
03-hpl-1node.sbatch      — Single-node HPL (FP64)
03-hpl-8node.sbatch      — Full-cluster HPL (FP64)
03-hpl-1node.dat         — HPL input for 1 node / 8 GPUs
03-hpl-8node.dat         — HPL input for 8 nodes / 64 GPUs
04-hpl-mxp-1node.sbatch  — Single-node HPL-MxP
04-hpl-mxp-8node.sbatch  — Full-cluster HPL-MxP
README.md                — This file
```

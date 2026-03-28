#!/bin/bash
#SBATCH --job-name=stream-gpu
#SBATCH --output=stream-gpu_%j.out
#SBATCH --error=stream-gpu_%j.err
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=8
#SBATCH --gres=gpu:8
#SBATCH --time=00:15:00
#SBATCH --exclusive
##SBATCH --partition=<your-gpu-partition>

# =============================================================================
# NVIDIA STREAM GPU Benchmark — AI Cluster (1 node, 8 × H200)
# Measures sustainable HBM3e memory bandwidth per GPU.
# Expected TRIAD: ~4,300,000 - 4,600,000 MB/s (FP64), ~90-95% of 4.8 TB/s peak
# (STREAM reports in MB/s; 4.8 TB/s = 4,800,000 MB/s)
# =============================================================================

# --- Container path (adjust to your SIF location) ---
SIF=/p/data/work/dots-pa/containers/hpc-benchmarks-25.09.sif

# --- Results directory ---
RESULTS_DIR=/p/data/work/dots-pa/hpc-benchmarks/results/stream
mkdir -p ${RESULTS_DIR}

echo "=========================================="
echo "STREAM GPU Benchmark"
echo "Date:  $(date)"
echo "Nodes: ${SLURM_NNODES}"
echo "GPUs:  $((SLURM_NNODES * 8))"
echo "Host:  $(hostname)"
echo "=========================================="

# Run STREAM on all 8 GPUs — FP64 (double precision) — the default
# --t CST runs COPY, SCALE, and TRIAD tests (omit A for ADD if desired;
# use default --t CSAT for all four: COPY, SCALE, ADD, TRIAD)
srun --mpi=pmix --cpu-bind=none \
    apptainer exec --nv \
        --bind /run,/var \
        ${SIF} \
    /workspace/cuda12/stream-gpu-test.sh

echo ""
echo "=========================================="
echo "STREAM FP32 (single precision) run"
echo "=========================================="

# Also run FP32 for comparison — flag is --dt fp32 (not --fp32)
srun --mpi=pmix --cpu-bind=none \
    apptainer exec --nv \
        --bind /run,/var \
        ${SIF} \
    /workspace/cuda12/stream-gpu-test.sh \
        --dt fp32

echo ""
echo "STREAM benchmark complete: $(date)"

# Copy output to results
cp ${SLURM_SUBMIT_DIR}/stream-gpu_${SLURM_JOB_ID}.out ${RESULTS_DIR}/

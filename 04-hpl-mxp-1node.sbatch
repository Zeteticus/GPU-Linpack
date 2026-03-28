#!/bin/bash
#SBATCH --job-name=hpl-mxp-1node
#SBATCH --output=hpl-mxp-1node_%j.out
#SBATCH --error=hpl-mxp-1node_%j.err
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=8
#SBATCH --gres=gpu:8
#SBATCH --time=02:00:00
#SBATCH --exclusive
##SBATCH --partition=<your-gpu-partition>

# =============================================================================
# NVIDIA HPL-MxP Benchmark — AI Cluster (1 node, 8 × H200)
# Mixed-precision Linpack using Tensor Cores (FP16 LU factorization
# with iterative refinement to FP64 accuracy).
# Shows AI-relevant peak compute per GPU.
# =============================================================================

SIF=/p/data/work/dots-pa/containers/hpc-benchmarks-25.09.sif

RESULTS_DIR=/p/data/work/dots-pa/hpc-benchmarks/results/hpl-mxp
mkdir -p ${RESULTS_DIR}

echo "=========================================="
echo "HPL-MxP Benchmark — 1 Node (8 × H200 GPUs)"
echo "Date:    $(date)"
echo "Host:    $(hostname)"
echo "N:       485376"
echo "NB:      2048"
echo "P×Q:     2×4 = 8 processes (row-major)"
echo "Sloppy:  FP16"
echo "=========================================="

# --- CPU/Memory/GPU affinity for XE9680 ---
CPU_AFFINITY="0-13:14-27:28-41:42-55:56-69:70-83:84-97:98-111"
MEM_AFFINITY="0:0:0:0:1:1:1:1"
GPU_AFFINITY="0:1:2:3:4:5:6:7"

srun --mpi=pmix --cpu-bind=none \
    apptainer exec --nv \
        --bind /run,/var \
        ${SIF} \
    /workspace/cuda12/hpl-mxp.sh \
        --n 485376 \
        --nb 2048 \
        --nprow 2 \
        --npcol 4 \
        --nporder row \
        --gpu-affinity ${GPU_AFFINITY} \
        --cpu-affinity ${CPU_AFFINITY} \
        --mem-affinity ${MEM_AFFINITY} \
        --sloppy-type FP16

echo ""
echo "HPL-MxP 1-node complete: $(date)"
cp ${SLURM_SUBMIT_DIR}/hpl-mxp-1node_${SLURM_JOB_ID}.out ${RESULTS_DIR}/

#!/bin/bash
#SBATCH --job-name=hpl-mxp-8node
#SBATCH --output=hpl-mxp-8node_%j.out
#SBATCH --error=hpl-mxp-8node_%j.err
#SBATCH --nodes=8
#SBATCH --ntasks-per-node=8
#SBATCH --gres=gpu:8
#SBATCH --time=04:00:00
#SBATCH --exclusive
##SBATCH --partition=<your-gpu-partition>

# =============================================================================
# NVIDIA HPL-MxP Benchmark — AI Cluster FULL CLUSTER (8 nodes, 64 × H200)
# Mixed-precision Linpack — Tensor Core peak across the full fabric.
#
# N=901120, NB=2048
# P×Q = 8×8 = 64 MPI ranks (row-major)
# Sloppy type: FP16 (can also try FP8 for even higher Tensor Core throughput)
# =============================================================================

SIF=/home/ascensus/containers/hpc-benchmarks-25.09.sif

RESULTS_DIR=/home/ascensus/hpc-benchmarks/results/hpl-mxp
mkdir -p ${RESULTS_DIR}

echo "=========================================="
echo "HPL-MxP Benchmark — 8 Nodes (64 × H200 GPUs)"
echo "Date:     $(date)"
echo "Nodes:    ${SLURM_NNODES}"
echo "Nodelist: ${SLURM_NODELIST}"
echo "N:        901120"
echo "NB:       2048"
echo "P×Q:      8×8 = 64 processes (row-major)"
echo "Sloppy:   FP16"
echo "=========================================="

# --- CPU/Memory/GPU affinity for XE9680 ---
CPU_AFFINITY="0-13:14-27:28-41:42-55:56-69:70-83:84-97:98-111"
MEM_AFFINITY="0:0:0:0:1:1:1:1"
GPU_AFFINITY="0:1:2:3:4:5:6:7"

# --- UCX / InfiniBand tuning (uncomment and adjust if needed) ---
# export UCX_TLS=rc,sm,cuda_copy,cuda_ipc,gdr_copy
# export UCX_NET_DEVICES=mlx5_0:1,mlx5_1:1,mlx5_2:1,mlx5_3:1

srun --mpi=pmix --cpu-bind=none \
    apptainer exec --nv \
        --bind /run,/var \
        ${SIF} \
    /workspace/cuda12/hpl-mxp.sh \
        --n 901120 \
        --nb 2048 \
        --nprow 8 \
        --npcol 8 \
        --nporder row \
        --gpu-affinity ${GPU_AFFINITY} \
        --cpu-affinity ${CPU_AFFINITY} \
        --mem-affinity ${MEM_AFFINITY} \
        --sloppy-type FP16

echo ""
echo "HPL-MxP 8-node complete: $(date)"
echo "Look for both 'GFLOPS' (overall) and 'LU GFLOPS' (Tensor Core peak)."
cp ${SLURM_SUBMIT_DIR}/hpl-mxp-8node_${SLURM_JOB_ID}.out ${RESULTS_DIR}/

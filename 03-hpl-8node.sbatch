#!/bin/bash
#SBATCH --job-name=hpl-8node
#SBATCH --output=hpl-8node_%j.out
#SBATCH --error=hpl-8node_%j.err
#SBATCH --nodes=8
#SBATCH --ntasks-per-node=8
#SBATCH --gres=gpu:8
#SBATCH --time=04:00:00
#SBATCH --exclusive
##SBATCH --partition=<your-gpu-partition>

# =============================================================================
# NVIDIA HPL Benchmark — AI Cluster FULL CLUSTER (8 nodes, 64 × H200)
#
# This is THE stress test. Dense FP64 Linpack across all 64 GPUs.
# Saturates compute, NVLink, AND InfiniBand NDR simultaneously.
# This WILL expose GDR issues — if GPU Direct RDMA is broken,
# per-GPU GFLOPS will drop dramatically vs the 1-node baseline.
#
# N=972800 targets ~80% of per-GPU HBM (64×141GB ≈ 9 TB aggregate)
# P×Q = 8×8 = 64 MPI ranks (1 per GPU)
# =============================================================================

SIF=/home/ascensus/containers/hpc-benchmarks-25.09.sif

RESULTS_DIR=/home/ascensus/hpc-benchmarks/results/hpl
mkdir -p ${RESULTS_DIR}

WORK_DIR=${RESULTS_DIR}/run_8node_${SLURM_JOB_ID}
mkdir -p ${WORK_DIR}
cp ${SLURM_SUBMIT_DIR}/03-hpl-8node.dat ${WORK_DIR}/HPL.dat

echo "=========================================="
echo "HPL Benchmark — 8 Nodes (64 × H200 GPUs)"
echo "Date:     $(date)"
echo "Nodes:    ${SLURM_NNODES}"
echo "Nodelist: ${SLURM_NODELIST}"
echo "N:        972800"
echo "NB:       1024"
echo "P×Q:      8×8 = 64 processes"
echo "=========================================="

# --- CPU/Memory affinity for XE9680 ---
CPU_AFFINITY="0-13:14-27:28-41:42-55:56-69:70-83:84-97:98-111"
MEM_AFFINITY="0:0:0:0:1:1:1:1"

# --- HPL environment tuning ---
export WARMUP_END_PROG=5
export HPL_USE_NVSHMEM=0

# --- UCX / InfiniBand tuning (uncomment and adjust if needed) ---
# export UCX_TLS=rc,sm,cuda_copy,cuda_ipc,gdr_copy
# export UCX_NET_DEVICES=mlx5_0:1,mlx5_1:1,mlx5_2:1,mlx5_3:1
# export NCCL_IB_HCA=mlx5_0,mlx5_1,mlx5_2,mlx5_3

srun --mpi=pmix --cpu-bind=none \
    apptainer exec --nv \
        --bind ${WORK_DIR}:/hpl-work \
        --bind /run,/var \
        ${SIF} \
    /workspace/cuda12/hpl.sh \
        --dat /hpl-work/HPL.dat \
        --cpu-affinity ${CPU_AFFINITY} \
        --mem-affinity ${MEM_AFFINITY}

echo ""
echo "HPL 8-node complete: $(date)"
echo "Check output for 'WC00L2L2' line — that's your Rmax GFLOPS."
cp ${SLURM_SUBMIT_DIR}/hpl-8node_${SLURM_JOB_ID}.out ${RESULTS_DIR}/

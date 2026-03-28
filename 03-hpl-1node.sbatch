#!/bin/bash
#SBATCH --job-name=hpl-1node
#SBATCH --output=hpl-1node_%j.out
#SBATCH --error=hpl-1node_%j.err
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=8
#SBATCH --gres=gpu:8
#SBATCH --time=02:00:00
#SBATCH --exclusive
##SBATCH --partition=<your-gpu-partition>

# =============================================================================
# NVIDIA HPL Benchmark — AI Cluster (1 node, 8 × H200)
# Dense FP64 Linpack — the TOP500 benchmark.
# Saturates GPU compute + NVLink intra-node.
# =============================================================================

SIF=/p/data/work/dots-pa/containers/hpc-benchmarks-25.09.sif

RESULTS_DIR=/p/data/work/dots-pa/hpc-benchmarks/results/hpl
mkdir -p ${RESULTS_DIR}

# --- Copy the .dat file to a writable location (HPL writes output files) ---
WORK_DIR=${RESULTS_DIR}/run_1node_${SLURM_JOB_ID}
mkdir -p ${WORK_DIR}
cp ${SLURM_SUBMIT_DIR}/03-hpl-1node.dat ${WORK_DIR}/HPL.dat

echo "=========================================="
echo "HPL Benchmark — 1 Node (8 × H200 GPUs)"
echo "Date:    $(date)"
echo "Host:    $(hostname)"
echo "N:       344064"
echo "NB:      1024"
echo "P×Q:     2×4 = 8 processes"
echo "=========================================="

# --- CPU/Memory affinity for XE9680 ---
CPU_AFFINITY="0-13:14-27:28-41:42-55:56-69:70-83:84-97:98-111"
MEM_AFFINITY="0:0:0:0:1:1:1:1"

# --- HPL environment tuning ---
export WARMUP_END_PROG=5
export HPL_USE_NVSHMEM=0
# NVSHMEM disabled by default to avoid known MPICH issues (see release notes).
# Enable with HPL_USE_NVSHMEM=1 if your MPI stack supports it.

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
echo "HPL 1-node complete: $(date)"
cp ${SLURM_SUBMIT_DIR}/hpl-1node_${SLURM_JOB_ID}.out ${RESULTS_DIR}/

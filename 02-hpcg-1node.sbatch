#!/bin/bash
#SBATCH --job-name=hpcg-1node
#SBATCH --output=hpcg-1node_%j.out
#SBATCH --error=hpcg-1node_%j.err
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=8
#SBATCH --gres=gpu:8
#SBATCH --time=00:30:00
#SBATCH --exclusive
##SBATCH --partition=<your-gpu-partition>

# =============================================================================
# NVIDIA HPCG Benchmark — AI Cluster (1 node, 8 × H200)
# Stresses memory bandwidth, sparse data movement, and intra-node NVLink.
# HPCG is the TOP500 companion benchmark (HPCG500 list).
# =============================================================================

SIF=/home/ascensus/containers/hpc-benchmarks-25.09.sif

RESULTS_DIR=/home/ascensus/hpc-benchmarks/results/hpcg
mkdir -p ${RESULTS_DIR}

echo "=========================================="
echo "HPCG Benchmark — 1 Node (8 GPUs)"
echo "Date:  $(date)"
echo "Host:  $(hostname)"
echo "=========================================="

# --- HPCG parameters ---
# nx, ny, nz: local problem dimensions per MPI process (per GPU)
# For H200 (141 GB HBM3e), 512×512×288 is a good fit
# rt: runtime in seconds for the timed portion (use 60 for quick test, 1860 for official)
# Use rt=60 for validation, rt=1860 (31 min) for a submittable result

NX=512
NY=512
NZ=288
RT=60   # Change to 1860 for official/submittable run

# --- CPU/Memory affinity for XE9680 (DGX-H100 compatible topology) ---
# Adjust if your Xeon core count differs — verify with: lscpu | grep "NUMA"
CPU_AFFINITY="0-13:14-27:28-41:42-55:56-69:70-83:84-97:98-111"
MEM_AFFINITY="0:0:0:0:1:1:1:1"

srun --mpi=pmix --cpu-bind=none \
    apptainer exec --nv \
        --bind /run,/var \
        ${SIF} \
    /workspace/cuda12/hpcg.sh \
        --nx ${NX} --ny ${NY} --nz ${NZ} --rt ${RT} \
        --cpu-affinity ${CPU_AFFINITY} \
        --mem-affinity ${MEM_AFFINITY}

echo ""
echo "HPCG 1-node complete: $(date)"
cp ${SLURM_SUBMIT_DIR}/hpcg-1node_${SLURM_JOB_ID}.out ${RESULTS_DIR}/

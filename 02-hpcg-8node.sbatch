#!/bin/bash
#SBATCH --job-name=hpcg-8node
#SBATCH --output=hpcg-8node_%j.out
#SBATCH --error=hpcg-8node_%j.err
#SBATCH --nodes=8
#SBATCH --ntasks-per-node=8
#SBATCH --gres=gpu:8
#SBATCH --time=01:00:00
#SBATCH --exclusive
##SBATCH --partition=<your-gpu-partition>

# =============================================================================
# NVIDIA HPCG Benchmark — AI Cluster FULL CLUSTER (8 nodes, 64 × H200)
# Stresses memory, sparse data movement, NVLink + InfiniBand NDR.
# =============================================================================

SIF=/home/ascensus/containers/hpc-benchmarks-25.09.sif

RESULTS_DIR=/home/ascensus/hpc-benchmarks/results/hpcg
mkdir -p ${RESULTS_DIR}

echo "=========================================="
echo "HPCG Benchmark — 8 Nodes (64 GPUs)"
echo "Date:  $(date)"
echo "Nodes: ${SLURM_NNODES}"
echo "Nodelist: ${SLURM_NODELIST}"
echo "=========================================="

NX=512
NY=512
NZ=288
RT=60   # Change to 1860 for official/submittable run

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
echo "HPCG 8-node complete: $(date)"
cp ${SLURM_SUBMIT_DIR}/hpcg-8node_${SLURM_JOB_ID}.out ${RESULTS_DIR}/

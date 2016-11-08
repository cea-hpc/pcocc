#!/bin/bash
#  Copyright (C) 2014-2015 CEA/DAM/DIF
#
#  This file is part of PCOCC, a tool to easily create and deploy
#  virtual machines using the resource manager of a compute cluster.
#
#  PCOCC is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  PCOCC is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with PCOCC. If not, see <http://www.gnu.org/licenses/>
#
#  Written by Francois Diakhate <francois.diakhate@cea.fr>


# Generates a basic slurm configuration file for a cluster of vm
# The number of VM can be specified on the command line or guessed from the number of slurm tasks

if [[ -n $1 ]]; then
    NTASKS=$1
elif [[ -n ${SLURM_NTASKS} ]]; then
    NTASKS=$SLURM_NTASKS
else
    NTASKS=1
fi

if [[ -n $2 ]]; then
    NCPUS=$2
elif [[ -n ${SLURM_CPUS_PER_TASK} ]]; then
    NCPUS=$SLURM_CPUS_PER_TASK
else
    NCPUS=1
fi

if [[ -n $3 ]]; then
    MEM=$2
else
    JOBINFO=$(scontrol show jobid="${SLURM_JOBID}" 2>/dev/null)
    MEM=$(echo $JOBINFO | grep -o -E 'MinMemoryCPU=([[:digit:]])+M'  | grep -o -E '[[:digit:]]+')
    if [[ -n "$MEM" ]]; then
	MEM=$(( ${MEM} * ${NCPUS} ))
    else
        #Assume the memory was specified on a per Node basis
	MEM=$(echo $JOBINFO | grep -o -E 'MinMemoryNode=([[:digit:]])+M'  | grep -o -E '[[:digit:]]+')
       if [[ -z "$MEM" ]]; then
	   MEM=$(echo $JOBINFO | grep -o -E 'MinMemoryNode=([[:digit:]])+G'  | grep -o -E '[[:digit:]]+')
           MEM=$(( $MEM * 1024 ))
	   if [[ -z $MEM ]]; then
               MEM=1
	   fi
       fi
    fi
fi


if [[ ! -d "slurm" ]]; then
    mkdir slurm
fi

cat <<SLURM_EOF > slurm/slurm.conf

ClusterName=vm
ControlMachine=vm0
SlurmUser=slurm
SlurmctldPort=6817
SlurmdPort=6818
MpiParams=ports=12000-16999
AuthType=auth/munge
StateSaveLocation=/tmp/slurmctld
SlurmdSpoolDir=/tmp/slurmd
SwitchType=switch/none
MpiDefault=none
SlurmctldPidFile=/var/run/slurmctld.pid
SlurmdPidFile=/var/run/slurmd.pid
ProctrackType=proctrack/cgroup
CacheGroups=0
ReturnToService=0
PropagateResourceLimits=MEMLOCK,NOFILE,FSIZE,STACK,CORE
SlurmctldTimeout=300
SlurmdTimeout=300
InactiveLimit=0
MinJobAge=300
KillWait=30
Waittime=0
BatchStartTimeout=90
MessageTimeout=90

#
# TASKS BINDING
TaskPlugin=task/cgroup
TaskPluginParam=Cpusets,Cores

# SCHEDULING
SelectType=select/cons_res
# Allocate nodes based on core resources
# Allocate cores on nodes using a block distribution by default (fill sockets)
# Do not treat hyperthreads as cores by default
SelectTypeParameters=CR_Core,CR_CORE_DEFAULT_DIST_BLOCK,CR_ONE_TASK_PER_CORE
SchedulerType=sched/backfill
FastSchedule=2

# LOGGING
SlurmctldDebug=3
SlurmctldLogFile=/var/log/slurmctld.log
SlurmdDebug=3
SlurmdLogFile=/var/log/slurmd.log
JobCompType=jobcomp/none

# COMPUTE NODES
NodeName=vm[0-$(( ${NTASKS} - 1 ))] CPUS=${NCPUS} State=UNKNOWN RealMemory=$MEM
PartitionName=vm Nodes=vm[0-$(( ${NTASKS} - 1 ))] Default=YES MaxTime=INFINITE State=UP

SLURM_EOF

chmod 644 slurm/slurm.conf
chmod 755 slurm

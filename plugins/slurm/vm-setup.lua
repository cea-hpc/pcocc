--  Copyright (C) 2014-2015 CEA/DAM/DIF
--
--  This file is part of PCOCC, a tool to easily create and deploy
--  virtual machines using the resource manager of a compute cluster.
--
--  PCOCC is free software: you can redistribute it and/or modify
--  it under the terms of the GNU General Public License as published by
--  the Free Software Foundation, either version 3 of the License, or
--  (at your option) any later version.
--
--  PCOCC is distributed in the hope that it will be useful,
--  but WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--  GNU General Public License for more details.
--
--  You should have received a copy of the GNU General Public License
--  along with PCOCC. If not, see <http://www.gnu.org/licenses/>
--
--  Written by Francois Diakhate <francois.diakhate@cea.fr>

require "posix"

local vm_enabled = false

-- set logging primitives
local debug = SPANK.log_debug
local verbose = SPANK.log_verbose
local error = SPANK.log_error

-- helper function to log external commands
function do_and_log_output (cmd)
   debug("lua/vmsetup: executing %s", cmd)
   local f = assert(io.popen(cmd.." 2>&1"))
   local ret = true
   for line in f:lines()
   do
      error("lua/vmsetup: %s",line)
      ret = false
   end
   f:close()

   return ret
end

-- Callback to set global vars if the plugin is enabled
function option_handler (v, arg, remote)
   vm_enabled = true
   vm_option = arg
end

-- Unfortuntately slurm environment variables aren't set in this
-- context so we replicate them by hand.
function replicate_slurm_vars (spank)
      local jobid = spank:get_item  ("S_JOB_ID")
      local jobuid = spank:get_item ("S_JOB_UID")
      posix.setenv("SLURM_JOB_ID", jobid, 1)
      posix.setenv("SLURM_JOB_UID", jobuid, 1)

      local tpn = spank:getenv ("SLURM_STEP_TASKS_PER_NODE")
      local nodelist = spank:getenv ("SLURM_STEP_NODELIST")
      posix.setenv("SLURM_TASKS_PER_NODE", tpn, 1)
      posix.setenv("SLURM_NODELIST", nodelist, 1)

      local credential = spank:getenv ("PCOCC_REQUEST_CRED")
      posix.setenv("SPANK_PCOCC_REQUEST_CRED", credential, 1)
      posix.setenv("SPANK_PCOCC_SETUP", vm_option, 1)
end

function slurm_spank_init(spank)
   -- register our option
   vm_spank_opt =  {
      name = "vm",
      usage = "Setup the nodes for pcocc VMs",
      cb = "option_handler",
      val = "vm",
      has_arg = 1,
      arginfo = "pcocc_opt"
   }

   spank:register_option(vm_spank_opt)

   return SPANK.SUCCESS
end

function pcocc_node_setup(spank)
   for i,arg in pairs(spank.args) do
      debug("%s",arg)
      path = arg:match("^pcocc_path=(.*)")
      if path then
         return path..'/bin/pcocc'
      end
   end

   return '/usr/bin/pcocc'
end

-- This is called after options have been processed
function slurm_spank_init_post_opt (spank)
   debug("lua/vmsetup: init_post_op")

   if not vm_enabled then
      return SPANK.SUCCESS
   end

   debug("lua/vmsetup: init_post_op: vm_enabled")
   if spank.context ~= "remote" then
      -- Called in srun/salloc context: setup
      debug("lua/vmsetup: init_post_op: allocator/local context")
      local rc, msg = spank:job_control_setenv ("PCOCC_SETUP", vm_option, 1)

      if rc == nil then
         SPANK.log_error ("Failed to propagate SETUP: %s", msg)
         return SPANK.FAILURE
      end
   else
      -- Called on the node
      local stepid = spank:get_item ("S_JOB_STEPID")
      if stepid == 0 then
            debug("lua/vmsetup: init_post_op: remote context")
            replicate_slurm_vars(spank)

            do_and_log_output(pcocc_node_setup(spank).." internal setup init")
            do_and_log_output(pcocc_node_setup(spank).." internal setup create")
      end
   end

   return SPANK.SUCCESS
end

function slurm_spank_exit (spank)
   debug("lua/vmsetup: exit")

   if not vm_enabled then
      return SPANK.SUCCESS
   end

   if spank.context == "remote" then
      local stepid = spank:get_item ("S_JOB_STEPID")
      if stepid == 0 then
            debug("lua/vmsetup: exit: remote context")
      	    replicate_slurm_vars(spank)
      	    do_and_log_output(pcocc_node_setup(spank).." internal setup delete")
       end
   end

   return SPANK.SUCCESS
end

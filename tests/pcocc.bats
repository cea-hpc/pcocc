setup() {
  bats_require_minimum_version 1.5.0
  bats_load_library bats-support
  bats_load_library bats-assert
}

teardown() {
  # Belt-and-braces in case a prior test left an allocation behind.
  scancel --me >/dev/null 2>&1 || true
}

# --- CLI surface ----------------------------------------------------------

@test "pcocc --help exits 0 and shows usage" {
  run -0 pcocc --help
  assert_line --partial 'Usage:'
}

@test "pcocc template list includes the test-tpl system template" {
  run -0 pcocc template list
  assert_output --partial 'test-tpl'
}

@test "pcocc template show test-tpl reports its image path" {
  run -0 pcocc template show test-tpl
  assert_output --partial '/var/pcocc/images/test'
  assert_output --partial 'default'
}

@test "pcocc image list runs without error against the user repo" {
  run -0 pcocc image list
}

# --- Cluster orchestration ------------------------------------------------

@test "etcd is reachable from the login node" {
  run -0 curl -sf http://etcd:2379/version
  assert_output --partial 'etcdserver'
}

@test "plain slurm jobs run on the test partition" {
  run -0 srun -n1 --partition=part1 /bin/true
}

@test "pcocc image import + alloc + ssh into Alpine VM" {
  # Full lifecycle: import an Alpine NoCloud cloud-init image, define a
  # user template that injects an SSH key via user-data, allocate, then
  # actually `pcocc ssh` in over the reverse-NAT'd port and run a command.
  mkdir -p ~/.ssh
  rm -f ~/.ssh/pcocc_test ~/.ssh/pcocc_test.pub
  ssh-keygen -t ed25519 -f ~/.ssh/pcocc_test -N '' -q
  local pubkey
  pubkey=$(cat ~/.ssh/pcocc_test.pub)

  mkdir -p ~/.pcocc
  cat > ~/.pcocc/templates.yaml <<EOF
alpine:
  image: user:alpine
  resource-set: default
  cpu-model: qemu64
  description: Alpine NoCloud test VM
  user-data:
    ssh_pwauth: false
    ssh_authorized_keys:
      - $pubkey
EOF
  pcocc image list | grep -q '^alpine' || \
    pcocc image import /opt/alpine.qcow2 user:alpine

  local probe
  probe=$(mktemp)
  cat > "$probe" <<'EOF'
#!/bin/sh
for i in $(seq 1 60); do
  out=$(timeout 6 pcocc ssh -- -i ~/.ssh/pcocc_test -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=4 -o BatchMode=yes alpine@vm0 echo VM_REACHED 2>&1 || true)
  if echo "$out" | grep -q VM_REACHED; then echo "SSH_UP"; exit 0; fi
  sleep 4
done
echo "NO_VM_RESPONSE"
exit 1
EOF
  chmod +x "$probe"
  run pcocc alloc -J pcocc -E "$probe" alpine:1
  rm -f "$probe"
  assert_output --partial 'Granted job allocation'
  assert_output --partial 'SSH_UP'
}

@test "pcocc alloc runs an -E host script end-to-end" {
  # Real end-to-end run: pcocc allocates the cluster (slurm + spank + ovs
  # + dnsmasq + netns), runs the -E script on the allocation node, then
  # tears the cluster down. We use a non-bootable placeholder qcow2; the
  # host script doesn't need the VM to actually boot to fire.
  local script
  script=$(mktemp)
  cat > "$script" <<'EOF'
#!/bin/sh
echo HOST_SCRIPT_RAN
EOF
  chmod +x "$script"
  run -0 pcocc alloc -E "$script" test-tpl:1
  rm -f "$script"
  assert_output --partial 'Granted job allocation'
  assert_output --partial 'Configuring hosts'
  assert_output --partial 'HOST_SCRIPT_RAN'
  assert_output --partial 'Terminating the cluster'
}

@test "pcocc alloc --image overrides the template boot image" {
  # test-tpl points at a 1 MiB non-bootable placeholder qcow2. Booting it
  # with --image user:alpine must instead start the real Alpine image: if
  # the override is honoured the VM boots and SSH comes up; if it is not,
  # the placeholder boots and the probe times out. So SSH_UP is a strict
  # discriminator that the CLI override actually reached the hypervisor.
  mkdir -p ~/.ssh
  rm -f ~/.ssh/pcocc_test ~/.ssh/pcocc_test.pub
  ssh-keygen -t ed25519 -f ~/.ssh/pcocc_test -N '' -q
  local pubkey
  pubkey=$(cat ~/.ssh/pcocc_test.pub)

  pcocc image list | grep -q '^alpine' || \
    pcocc image import /opt/alpine.qcow2 user:alpine

  # --user-data is consumed by `pcocc internal run` on the compute node, so
  # the file must live on shared storage (home), not the login node's /tmp.
  local userdata=~/.pcocc/test-userdata.yaml
  mkdir -p ~/.pcocc
  cat > "$userdata" <<EOF
#cloud-config
ssh_pwauth: false
ssh_authorized_keys:
  - $pubkey
EOF

  local probe
  probe=$(mktemp)
  cat > "$probe" <<'EOF'
#!/bin/sh
for i in $(seq 1 60); do
  out=$(timeout 6 pcocc ssh -- -i ~/.ssh/pcocc_test -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=4 -o BatchMode=yes alpine@vm0 echo VM_REACHED 2>&1 || true)
  if echo "$out" | grep -q VM_REACHED; then echo "SSH_UP"; exit 0; fi
  sleep 4
done
echo "NO_VM_RESPONSE"
exit 1
EOF
  chmod +x "$probe"
  run pcocc alloc -J pcocc --image user:alpine --user-data "$userdata" \
    -E "$probe" test-tpl:1
  rm -f "$probe" "$userdata"
  assert_output --partial 'Granted job allocation'
  assert_output --partial 'SSH_UP'
}

@test "pcocc alloc with two VMs on two nodes can ping each other" {
  # Two Alpine VMs, one on each compute node; verify L3 connectivity
  # over the internal VXLAN-backed network by SSH-ing into vm0 and
  # pinging vm1.  We resolve the VM name with getent before pinging
  # because Alpine BusyBox ping uses musl getaddrinfo() which chokes
  # when dnsmasq has no AAAA record for the IPv4-only name.
  # -N2 forces Slurm to allocate two distinct nodes.
  mkdir -p ~/.ssh
  rm -f ~/.ssh/pcocc_test ~/.ssh/pcocc_test.pub
  ssh-keygen -t ed25519 -f ~/.ssh/pcocc_test -N '' -q
  local pubkey
  pubkey=$(cat ~/.ssh/pcocc_test.pub)

  mkdir -p ~/.pcocc
  cat > ~/.pcocc/templates.yaml <<EOF
alpine:
  image: user:alpine
  resource-set: default
  cpu-model: qemu64
  description: Alpine NoCloud test VM
  user-data:
    ssh_pwauth: false
    ssh_authorized_keys:
      - $pubkey
EOF

  pcocc image list | grep -q '^alpine' || \
    pcocc image import /opt/alpine.qcow2 user:alpine

  local probe
  probe=$(mktemp)
  cat > "$probe" <<'EOF'
#!/bin/sh
set -e
for i in $(seq 1 90); do
  out=$(timeout 5 pcocc ssh -- -i ~/.ssh/pcocc_test -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -o BatchMode=yes alpine@vm0 echo VM0_REACHED 2>&1 || true)
  if echo "$out" | grep -q VM0_REACHED; then break; fi
  sleep 2
done
for i in $(seq 1 90); do
  out=$(timeout 5 pcocc ssh -- -i ~/.ssh/pcocc_test -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -o BatchMode=yes alpine@vm1 echo VM1_REACHED 2>&1 || true)
  if echo "$out" | grep -q VM1_REACHED; then break; fi
  sleep 2
done
# Resolve DNS and then ping (BusyBox ping can't resolve names when
# dnsmasq lacks AAAA, so we use getent first, which works fine).
vm1_ip=$(pcocc ssh -- -i ~/.ssh/pcocc_test -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -o BatchMode=yes alpine@vm0 getent hosts vm1.pcocc 2>/dev/null | awk '{print $1}')
pcocc ssh -- -i ~/.ssh/pcocc_test -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -o BatchMode=yes alpine@vm0 -- ping -c 3 "$vm1_ip"
echo MULTI_VM_PING_OK > /dev/stderr
EOF
  chmod +x "$probe"
  run pcocc alloc -J pcocc -N2 -E "$probe" alpine:2
  rm -f "$probe"
  assert_output --partial 'Granted job allocation'
  assert_output --partial 'MULTI_VM_PING_OK'
}

@test "pcocc alloc --image rejects an unknown template qualifier" {
  run pcocc alloc --image nosuchtpl=user:alpine -E /bin/true test-tpl:1
  assert_failure
  assert_output --partial 'not part of the cluster definition'
}


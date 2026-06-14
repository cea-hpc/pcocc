FROM fedora:43 AS slurm-basenv
# Slurm build (matches example-project's setup)
RUN dnf -y install git jq dnf-utils util-linux dbus-devel munge pmix-devel gcc valgrind \
    procps-ng hwinfo libjwt-devel json-c-devel http-parser-devel rust cargo mysql mysql-server \
    bats lua-posix
RUN git clone --depth 1 --branch slurm-24-11-5-1 https://github.com/SchedMD/slurm.git
RUN yum-builddep -y slurm/slurm.spec
RUN cd slurm/ && ./configure --with-jwt --enable-pkgconfig --with-systemdsystemunitdir=/usr/lib/systemd/system  \
    --program-prefix= --prefix=/usr --exec-prefix=/usr \
    --bindir=/usr/bin --sbindir=/usr/sbin --sysconfdir=/etc/slurm \
    --datadir=/usr/share --includedir=/usr/include --libdir=/usr/lib64 \
    --libexecdir=/usr/libexec --localstatedir=/var --sharedstatedir=/var/lib \
    --mandir=/usr/share/man --infodir=/usr/share/info --runstatedir=/run  \
    --with-bpf --with-pmix  && make -j  && make install && make clean
RUN dnf -y install crudini
# Debug helpers
RUN dnf -y install procps less iproute tcpdump strace hostname nmap-ncat iputils man bind-utils

RUN useradd -r -u 350 slurm  && \
    useradd -r -u 360 slurmrestd

RUN mkdir /etc/slurm  && \
    dd if=/dev/urandom of=/etc/slurm/slurm.key bs=1024 count=1 && \
    chown slurm:slurm /etc/slurm/slurm.key && \
    chmod 600 /etc/slurm/slurm.key

RUN mkdir /var/spool/slurmd && chown slurm:slurm /var/spool/slurmd  && \
    mkdir /var/spool/slurmctld && chown slurm:slurm /var/spool/slurmctld  && \
    touch /var/log/slurmctld.log && chown slurm:slurm /var/log/slurmctld.log && \
    dd if=/dev/urandom of=/var/spool/slurmctld/jwt_hs256.key bs=256 count=1 && \
    chmod 600 /var/spool/slurmctld/jwt_hs256.key && \
    chown slurm /var/spool/slurmctld/jwt_hs256.key

RUN cp /slurm/etc/slurm.conf.example /etc/slurm/slurm.conf && \
    cp /slurm/etc/cgroup.conf.example /etc/slurm/cgroup.conf && \
    cp /slurm/etc/slurmdbd.conf.example /etc/slurm/slurmdbd.conf && \
    chmod 600 /etc/slurm/slurmdbd.conf && \
    chown slurm /etc/slurm/slurmdbd.conf && \
    echo 'include /etc/slurm/plugstack.conf.d/*' > /etc/slurm/plugstack.conf

RUN sed -i 's!linux0!localhost!' /etc/slurm/slurm.conf && \
    sed -i 's!linux\[1-32\]!localhost!' /etc/slurm/slurm.conf && \
    sed -i 's!.*SelectType=.*!SelectType=select/cons_tres!' /etc/slurm/slurm.conf && \
    sed -i "s!.*SelectTypeParameters=.*!SelectTypeParameters=CR_Core_Memory!" /etc/slurm/slurm.conf && \
    sed -i s'/#PrologFlags=/PrologFlags=contain/' /etc/slurm/slurm.conf && \
    sed -i 's|SlurmctldHost=localhost|SlurmctldHost=slurmctld|' /etc/slurm/slurm.conf && \
    sed -i 's/NodeName=localhost.*//' /etc/slurm/slurm.conf

RUN crudini --set /etc/slurm/slurm.conf ""  AccountingStorageType accounting_storage/slurmdbd  \
    --set /etc/slurm/slurm.conf ""  AccountingStorageHost slurmctld  \
    --set /etc/slurm/slurm.conf ""  AuthType auth/slurm \
    --set /etc/slurm/slurm.conf ""  CredType cred/slurm \
    --set /etc/slurm/slurm.conf ""  AuthAltTypes auth/jwt  \
    --set /etc/slurm/slurm.conf ""  AuthAltParameters jwt_key=/var/spool/slurmctld/jwt_hs256.key \
    --set /etc/slurm/slurm.conf ""  GresTypes gpu \
    --set /etc/slurm/slurm.conf ""  SlurmdParameters config_overrides \
    --set /etc/slurm/slurm.conf ""  PrivateData jobs \
    --set /etc/slurm/slurm.conf ""  SlurmdDebug verbose

RUN crudini --set /etc/slurm/slurmdbd.conf ""  DbdHost slurmctld  \
    --set /etc/slurm/slurmdbd.conf ""  DbdAddr slurmctld  \
    --set /etc/slurm/slurmdbd.conf ""  AuthType auth/slurm \
    --set /etc/slurm/slurmdbd.conf ""  AuthAltTypes auth/jwt  \
    --set /etc/slurm/slurmdbd.conf ""  AuthAltParameters jwt_key=/var/spool/slurmctld/jwt_hs256.key   \
    --set /etc/slurm/slurmdbd.conf ""  AllowNoDefAcct yes \
    --del /etc/slurm/slurmdbd.conf ""  StoragePass

RUN echo include /etc/slurm/partition.conf >> /etc/slurm/slurm.conf
RUN echo include /etc/slurm/nodes.conf >> /etc/slurm/slurm.conf
RUN adduser --uid 1000 user &&  usermod -aG wheel user && echo '%wheel ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

RUN mkdir /bats && cd /bats && git clone https://github.com/bats-core/bats-support && \
    git clone https://github.com/bats-core/bats-assert
# Let .bats files find the helpers via `load 'bats-support/load'` regardless
# of where the test file lives (the host bind-mounts the suite at /pcocc/tests).
ENV BATS_LIB_PATH=/bats

# Base service tweaks
RUN sed -i 's|resolve \[!UNAVAIL=return\]||' /etc/nsswitch.conf
COPY --chmod=0755 tests/docker/cgroup-init.sh /sbin/cgroup-init.sh
CMD [ "/sbin/cgroup-init.sh" ]


FROM slurm-basenv AS pcocc-base
# pcocc targets Python 3.6+ and uses stdlib modules removed in 3.13 (pipes, ...).
# Pin a 3.11 interpreter alongside the system python.
RUN dnf -y install python3.11 python3.11-devel \
    qemu-kvm qemu-system-x86 qemu-img \
    openvswitch openssh-clients openssh-server \
    socat genisoimage e2fsprogs xfsprogs curl \
    iptables-nft dnsmasq util-linux-core hwloc \
    lua-devel automake autoconf libtool make
# Build the SPANK Lua loader (third-party; not shipped by Slurm itself).
# spank_lua.so is what pcocc's vm-setup.lua needs to be invoked as a SPANK plugin.
# Using the Stanford fork that ships just the lua plugin extracted from the
# original LLNL slurm-spank-plugins.
RUN git clone --depth 1 https://github.com/stanford-rc/slurm-spank-lua.git /tmp/spank-lua && \
    cd /tmp/spank-lua && make && \
    install -m 0755 lua.so /usr/lib64/slurm/spank_lua.so && \
    rm -rf /tmp/spank-lua
RUN python3.11 -m ensurepip && python3.11 -m pip install --no-cache-dir \
    PyYAML 'python-etcd>=0.4.3' psutil jsonschema urllib3 dnspython ClusterShell \
    grpcio 'pyOpenSSL<23' 'protobuf<3.21' six click

# Bake a working install of pcocc into the image so the `pcocc` entry script
# is on PATH at boot. At runtime, compose bind-mounts the host repo at /pcocc
# and PYTHONPATH=/pcocc/lib overrides imports — edits on the host are picked
# up without rebuilding.
RUN mkdir -p /opt/pcocc-build /etc/pcocc /etc/slurm/lua.d /etc/slurm/plugstack.conf.d
COPY setup.py /opt/pcocc-build/setup.py
COPY lib /opt/pcocc-build/lib
COPY confs /opt/pcocc-build/confs
COPY plugins /opt/pcocc-build/plugins
COPY dist /opt/pcocc-build/dist
COPY helpers /opt/pcocc-build/helpers
COPY README.md MANIFEST.in setup.cfg /opt/pcocc-build/
RUN cd /opt/pcocc-build && python3.11 -m pip install --no-cache-dir .
# vm-setup.lua looks up `/usr/bin/pcocc` by default (or `<pcocc_path>/bin/pcocc`
# if passed via spank args). pip puts the entry point at /usr/local/sbin/pcocc;
# symlink so the plugstack's default resolution works.
RUN ln -sf /usr/local/sbin/pcocc /usr/bin/pcocc
RUN cp /opt/pcocc-build/plugins/slurm/vm-setup.lua /etc/slurm/lua.d/vm-setup.lua

# Minimal placeholder qcow2 for the `test-tpl` template. 1 MiB empty disk; just
# enough for pcocc to resolve the image path without erroring. Replace with a
# real bootable image when adding boot-level tests.
RUN mkdir -p /var/pcocc/images/test && \
    qemu-img create -f qcow2 /var/pcocc/images/test/image 1M

# Bake an Alpine cloud-init NoCloud image so tests can exercise
# `pcocc image import` and a full VM-boot path offline. The bios-cloudinit
# variant matches pcocc's default `-machine pc` (BIOS, not UEFI) and ships
# with cloud-init pre-installed, which lets the test inject an SSH key via
# pcocc's user-data + cloud_seed CD.
ADD https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/cloud/nocloud_alpine-3.22.0-x86_64-bios-cloudinit-r0.qcow2 /opt/alpine.qcow2
RUN chmod 0644 /opt/alpine.qcow2
COPY tests/docker/plugstack-pcocc.conf /etc/slurm/plugstack.conf.d/pcocc.conf
COPY tests/docker/pcocc/ /etc/pcocc/

# Make PYTHONPATH point at the mounted source for every process
RUN echo 'PYTHONPATH=/pcocc/lib' >> /etc/environment
ENV PYTHONPATH=/pcocc/lib

# Slurm config slices specific to the pcocc test cluster
COPY --chmod=0644 tests/docker/partition.conf /etc/slurm/
COPY --chmod=0644 tests/docker/nodes.conf /etc/slurm/


FROM pcocc-base AS slurmctld
COPY --chmod=0644 tests/docker/slurm_init.sql /slurm_init.sql
COPY --chmod=0644 tests/docker/mysqld_override.conf /etc/systemd/system/mysqld.service.d/override.conf
COPY --chmod=0644 tests/docker/slurmctld_override.conf /etc/systemd/system/slurmctld.service.d/override.conf
RUN systemctl enable slurmctld mysqld slurmdbd


FROM pcocc-base AS slurm-login
RUN systemctl enable sackd


FROM pcocc-base AS slurm-compute
# Enable services for a real compute node: slurmd, ovs
RUN systemctl enable slurmd openvswitch
# Make slurmd inherit PYTHONPATH=/pcocc/lib so spank-spawned `pcocc internal
# setup` runs the bind-mounted source rather than the baked-in install. Without
# this, code edits to lib/pcocc/* don't take effect on compute nodes without
# rebuilding.
RUN mkdir -p /etc/systemd/system/slurmd.service.d
COPY --chmod=0644 tests/docker/slurmd_pythonpath.conf /etc/systemd/system/slurmd.service.d/pythonpath.conf

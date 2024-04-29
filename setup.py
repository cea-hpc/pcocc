 #!/usr/bin/env python3
import os
import glob
from setuptools.command.bdist_rpm import bdist_rpm
from setuptools.command.install import install
from setuptools import setup, find_packages
from distutils.core import Extension

class pcocc_bdist_rpm(bdist_rpm):
    user_options = bdist_rpm.user_options + [
        ('macros=', None, 'Specfiy macros in RPM header')]

    def initialize_options(self):
        bdist_rpm.initialize_options(self)
        self.macros = None

    def _make_spec_file(self):
        spec = bdist_rpm._make_spec_file(self)
        if self.macros:
            spec = [ l.strip() for l in open(self.macros).readlines() ] + spec
        return spec

class pcocc_install(install):
    user_options = install.user_options + [
        ('unitdir=', None, 'Specfiy folder to install systemd units'),
        ('mandir=', None, 'Specfiy folder to install man pages'),
        ('sysconfdir=', None, 'Specfiy folder to install configuration files'),
        ('pkgdocdir=', None, 'Specfiy folder to install documentation files')]

    def initialize_options(self):
        self.unitdir = None
        self.mandir='share/man'
        self.pkgdocdir='share/doc/pcocc'
        self.sysconfdir='/etc'

        install.initialize_options(self)

    def finalize_options(self):
        self.distribution.data_files.append((os.path.join(self.sysconfdir, 'pcocc'),
                                             glob.glob('confs/*.yaml')))
        self.distribution.data_files.append((os.path.join(self.sysconfdir, 'pcocc/helpers/examples/'),
                                             glob.glob('helpers/examples/*')))
        self.distribution.data_files.append((os.path.join(self.mandir, 'man1'),
                                             glob.glob('docs/build/man/*.1')))
        self.distribution.data_files.append((os.path.join(self.mandir, 'man5'),
                                             glob.glob('docs/build/man/*.5')))
        self.distribution.data_files.append((os.path.join(self.mandir, 'man7'),
                                             glob.glob('docs/build/man/*.7')))

        self.distribution.data_files.append((os.path.join(self.sysconfdir, 'slurm/lua.d'),
                                             ['plugins/slurm/vm-setup.lua']))
        if self.unitdir:
            self.distribution.data_files+=[(self.unitdir, ['dist/pkeyd.service'])]

        self.distribution.data_files += recursive_scan_data_files(self.pkgdocdir, 'docs/build/html/')

        install.finalize_options(self)

def recursive_scan_data_files(dest, src):
   f_files=[]
   for root, dirs, f in os.walk(src):
      destdir = os.path.join(dest, root.replace(src, ""))
      local_files=[]
      for file in f:
         fpath = os.path.join(root, file)
         if os.path.isfile(fpath):
            local_files.append(fpath)
      f_files.append((destdir, local_files))
   return f_files


setup(name= 'pcocc', version= '0.7.4', description= 'Spawn VMs on a HPC Cluster',
      long_description= 'Pcocc  allows users of a HPC cluster '
      'to host their own clusters of VMs on compute nodes alongside regular '
      'jobs. This allows users to fully customize their software environnements '
      'for development, testing or facilitating application deployment. Compute '
      'nodes remain managed by the batch scheduler as usual, since the clusters '
      'of VMs are seen as regular jobs.',
      author= 'Francois Diakhate', author_email= 'francois.diakhate@cea.fr',
      license= "GPLv3", package_dir={'': 'lib'},
      packages=['pcocc', 'pcocc.scripts',
                'pcocc.scripts.Shine'],
      data_files= [],
      entry_points= '''
        [console_scripts]
        pcocc=pcocc.scripts.cmd:cli
      ''',
      install_requires=['PyYAML', 'python-etcd >= 0.4.3', 'psutil',
                        'jsonschema', 'urllib3', 'dnspython', 'ClusterShell',
                        'grpcio', 'pyOpenSSL', 'protobuf', 'six', 'click'],
      cmdclass={'bdist_rpm': pcocc_bdist_rpm,
                'install': pcocc_install}
)

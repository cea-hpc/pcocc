 #!/usr/bin/env python
import glob
from setuptools.command.bdist_rpm import bdist_rpm
from setuptools.command.install import install
from setuptools import setup, find_packages


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
        ('unitdir=', None, 'Specfiy folder to install systemd units')]

    def initialize_options(self):
        self.unitdir = None
        install.initialize_options(self)

    def finalize_options(self):
        if self.unitdir:
            self.distribution.data_files+=[(self.unitdir, ['dist/pkeyd.service'])]
        install.finalize_options(self)

setup(name= 'pcocc', version= '0.2.8', description= 'Spawn VMs on a HPC Cluster',
      long_description= 'Pcocc  allows users of a HPC cluster '
      'to host their own clusters of VMs on compute nodes alongside regular '
      'jobs. This allows users to fully customize their software environnements '
      'for development, testing or facilitating application deployment. Compute '
      'nodes remain managed by the batch scheduler as usual, since the clusters '
      'of VMs are seen as regular jobs.',
      author= 'Francois Diakhate', author_email= 'francois.diakhate@cea.fr',
      license= "GPLv3", package_dir={'': 'lib'},
      packages=['pcocc', 'pcocc.scripts', 'pcocc.scripts.click',
                'pcocc.scripts.Shine'],
      data_files=[('/etc/pcocc/',
                   ['confs/templates.yaml', 'confs/networks.yaml',
                    'confs/resources.yaml', 'confs/batch.yaml']),
                  ('/etc/slurm/lua.d/', ['plugins/slurm/vm-setup.lua']),
                  ('/etc/pcocc/helpers/examples', glob.glob('helpers/examples/*'))],
      entry_points= '''
        [console_scripts]
        pcocc=pcocc.scripts.cmd:cli
      ''',
      install_requires=['PyYAML', 'python-etcd >= 0.4.3', 'psutil',
                        'jsonschema', 'urllib3', 'dnspython', 'ClusterShell'],
      cmdclass={'bdist_rpm': pcocc_bdist_rpm,
                'install': pcocc_install}
)

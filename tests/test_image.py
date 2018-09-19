import pytest
import os
import subprocess
import pcocc.Image as Image
from pcocc.Error import PcoccError

def test_init_mgr(datadir):
   mgr = Image.ImageMgr()

   mgr.load_repos(str(datadir.join('repos1.yaml')),  'system')

   # Reload same repos
   with pytest.raises(PcoccError):
       mgr.load_repos(str(datadir.join('repos1.yaml')), 'user')

   # Load badly formatted repos
   with pytest.raises(PcoccError):
      mgr.load_repos(str(datadir.join('bad_repos.yaml')), 'user')

   # Load other repos
   mgr.load_repos(str(datadir.join('repos2.yaml')), None)

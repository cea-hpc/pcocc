import pytest
import os
from distutils import dir_util

import pcocc
from pcocc.Networks import VNetworkConfig
from pcocc.Error import InvalidConfigurationError

@pytest.fixture
def datadir(tmpdir, request):
    '''
    Fixture responsible for searching a folder with the same name of test
    module and, if available, moving all contents to a temporary directory so
    tests can use them freely.
    '''
    filename = request.module.__file__
    test_dir, _ = os.path.splitext(filename)

    if os.path.isdir(test_dir):
        dir_util.copy_tree(test_dir, bytes(tmpdir))

    return tmpdir


def test_network_config(datadir):
    vnets = VNetworkConfig()
    with pytest.raises(InvalidConfigurationError) as err:
        vnets.load('')
    assert 'No such file or directory' in str(err.value)

    vnets = VNetworkConfig()
    with pytest.raises(InvalidConfigurationError) as err:
        vnets.load(str(datadir.join('networks_syntax.yaml')))
    assert 'line 8' in str(err.value)

    vnets = VNetworkConfig()
    with pytest.raises(InvalidConfigurationError) as err:
        vnets.load(str(datadir.join('networks_unknown.yaml')))
    assert "'xxx' is not one of' in str(err.value)"

    vnets = VNetworkConfig()
    with pytest.raises(InvalidConfigurationError) as err:
        vnets.load(str(datadir.join('networks_toplevel.yaml')))
    assert 'line 6' in str(err.value)

    vnets = VNetworkConfig()
    with pytest.raises(InvalidConfigurationError) as err:
        vnets.load(str(datadir.join('networks_addparam.yaml')))
    assert "'foo' was unexpected" in str(err.value)

    vnets = VNetworkConfig()
    with pytest.raises(InvalidConfigurationError) as err:
        vnets.load(str(datadir.join('networks_badname.yaml')))
    print str(err.value)
    assert "'000badname' does not" in str(err.value)

    vnets = VNetworkConfig()
    vnets.load(str(datadir.join('networks_all.yaml')))
    assert(len(vnets) == 6)

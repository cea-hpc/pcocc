import pytest
import os

import pcocc
from pcocc.Networks import VNetworkConfig
from pcocc.Error import InvalidConfigurationError

@pytest.mark.parametrize("conf_file, expected_error", [
    ('networks_syntax.yaml', 'line 8'),
    ('networks_unknown.yaml',  "'xxx' is not one of"),
    ('networks_toplevel.yaml',  'line 6'),
    ('networks_addparam.yaml',  "'foo' was unexpected"),
    ('networks_badname.yaml',  "000badname"),
])
def test_bad_network_config(conf_file, expected_error, datadir):
    vnets = VNetworkConfig()
    with pytest.raises(InvalidConfigurationError) as err:
        vnets.load(str(datadir.join(conf_file)))
    assert expected_error in str(err.value)

def test_missing_network_config(datadir):
    vnets = VNetworkConfig()
    with pytest.raises(InvalidConfigurationError) as err:
        vnets.load('')
    assert 'No such file or directory' in str(err.value)

def test_good_network_config(datadir):
    vnets = VNetworkConfig()
    vnets.load(str(datadir.join('networks_all.yaml')))
    assert(len(vnets) == 6)

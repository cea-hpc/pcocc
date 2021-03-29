import pytest
import os

import pcocc
from pcocc.Templates import TemplateConfig
from pcocc.Resources  import ResSetConfig
from pcocc.Error import InvalidConfigurationError
from six import iteritems

def test_template_inheritance(datadir, config):
    config.tpls = TemplateConfig()
    config.rsets = ResSetConfig()

    config.rsets.load(str(datadir.join('resources.yaml')))
    config.tpls.load(str(datadir.join('templates_herit.yaml')), 'user')
    config.tpls.validate_inheritance()

    # Check that we have all templates and resource placeholders
    assert(len(config.tpls) == 5)

    # Test non-existing template
    with pytest.raises(KeyError):
      _ = config.tpls['not_found']

    # Test inheritance and overloading
    for attr, params in iteritems(pcocc.Templates.template_settings):
        if attr == 'placeholder' or attr == 'inherits':
            continue

        assert (getattr(config.tpls['example'], attr) !=
                getattr(config.tpls['overloads'], attr))

        if params[2]:
            assert (getattr(config.tpls['example'], attr) ==
                    getattr(config.tpls['herits'], attr))

        else:
            assert (getattr(config.tpls['herits'], attr) ==
                    params[1])

@pytest.mark.parametrize("conf_file, expected_error", [
    ('templates_syntax.yaml', 'line 5'),
    ('templates_missing.yaml', 'No such file'),
    ('templates_bad_herit.yaml', 'inherits from invalid template'),
    ('templates_bad_rset.yaml', 'invalid resource set'),
    ('templates_bad_name.yaml', 'restricted'),
])
def test_bad_templates(conf_file, expected_error, datadir, config):
    config.tpls = TemplateConfig()
    config.rsets = ResSetConfig()

    config.rsets.load(str(datadir.join('resources.yaml')))

    with pytest.raises(InvalidConfigurationError) as err:
        config.tpls.load(str(datadir.join(conf_file)), 'user', required=True)
        config.tpls.validate_inheritance()

    assert expected_error in str(err.value)


@pytest.mark.parametrize("template, expected_output", [
    ('example',
"""ATTRIBUTE         INHERITED    VALUE
---------         ---------    -----
disk-cache        No           writeback
user-data         No           example
nic-model         No           e1000
image             No           example
description       No           example
full-node         No           True
emulator-cores    No           2
resource-set      No           default
remote-display    No           spice
instance-id       No           example
mount-points      No           {'homedir': {'path': '/home'}}
qemu-bin          No           /path/to/qemu/bin/qemu-system-x86
custom-args       No           ['-cdrom', '/path/to/my-iso']
image-revision    No           N/A
machine-type      No           q35
kernel            No           aa
"""),
('herits',
"""ATTRIBUTE         INHERITED    VALUE
---------         ---------    -----
remote-display    Yes          spice
user-data         Yes          example
emulator-cores    Yes          2
mount-points      Yes          {'homedir': {'path': '/home'}}
qemu-bin          Yes          /path/to/qemu/bin/qemu-system-x86
full-node         Yes          True
inherits          No           example
nic-model         Yes          e1000
instance-id       Yes          example
custom-args       Yes          ['-cdrom', '/path/to/my-iso']
resource-set      Yes          default
disk-cache        Yes          writeback
image             Yes          example
image-revision    No           N/A
machine-type      Yes          q35
kernel            Yes          aa
"""),
])
def test_template_display(template, expected_output, capsys, datadir, config):
    config.tpls = TemplateConfig()
    config.rsets = ResSetConfig()

    config.rsets.load(str(datadir.join('resources.yaml')))
    config.tpls.load(str(datadir.join('templates_herit.yaml')), 'user')
    config.tpls.validate_inheritance()

    config.tpls[template].display()
    out, err = capsys.readouterr()
    assert sorted(out.splitlines()) == sorted(expected_output.splitlines())

@pytest.mark.parametrize("image_path, resolved_image, revision", [
    ('image_simple', 'image_simple/image', 0),
    ('image_rev', 'image_rev/image-rev3', 3),
    ('image_bad', None, 0),
    ('image', None, 0),
])
def test_template_resolve_image(image_path, resolved_image, revision,
                                monkeypatch, datadir, config):
    config.tpls = TemplateConfig()
    config.rsets = ResSetConfig()

    monkeypatch.setenv('EXAMPLE_IMAGE_PATH', str(datadir.join(image_path)))

    config.rsets.load(str(datadir.join('resources.yaml')))
    config.tpls.load(str(datadir.join('templates_images.yaml')), 'user',)
    config.tpls.validate_inheritance()

    if resolved_image:
        image, rev = config.tpls['example'].resolve_image()
        assert image.endswith(resolved_image)
        assert rev == revision
    else:
        with pytest.raises(InvalidConfigurationError):
            _, _ = config.tpls['example'].resolve_image()

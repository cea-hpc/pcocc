import pytest
import os
import subprocess
import pcocc.Image as Image



try:
    with open(os.devnull, 'w') as devnull:
        subprocess.call(["qemu-img"],
                        stdout=devnull,
                        stderr=devnull)
except OSError:
    pytest.skip("This test module needs qemu-img in the environment",
                allow_module_level=True)


def test_check_qemu_image_ext():
    for fmt in Image.known_vm_image_formats:
        assert Image.check_qemu_image_ext(fmt) is True

    with pytest.raises(Exception):
        Image.check_qemu_image_ext("whatisthis")


def test_create(datadir):

    # Test Create Fail
    img = str(datadir.join("thiswillneverbehere/out.qcow2"))
    with pytest.raises(Exception):
        Image.create(img, size="1M", iformat="qcow2")

    for fmt in Image.known_vm_image_formats:
        # No log
        img = str(datadir.join("image1." + fmt))
        Image.create( img, size="1M", iformat=fmt)
        assert os.path.isfile(img) is True
        # With Log
        img = str(datadir.join("image2." + fmt))
        Image.create( img, size="1M", iformat=fmt, quiet=False)
        assert os.path.isfile(img) is True


def test_convert(datadir):
    # Error no such file
    simg = str(datadir.join("whatisthis"))
    timg = str(datadir.join("whatisthis2"))
    with pytest.raises(Exception):
        Image.convert(simg, timg)
    assert os.path.isfile(timg) is False

    # Test auto-detect qcow2 when no ext
    simg = str(datadir.join("inq"))
    Image.create(simg, size="1M", iformat="qcow2")
    assert os.path.isfile(simg) is True
    timg = str(datadir.join("outq"))
    Image.convert(simg, timg)
    assert os.path.isfile(timg) is True

    # Test convert fail
    simg = str(datadir.join("inq"))
    assert os.path.isfile(simg) is True
    timg = str(datadir.join("thiswillneverbehere/out.qcow2"))
    with pytest.raises(Exception):
        Image.convert(simg, timg)


    # All formats
    for ifmt in Image.known_vm_image_formats:
        # First create a source image
        simg = str(datadir.join("source." + ifmt))
        Image.create(simg, size="1M", iformat=ifmt)
        assert os.path.isfile(simg) is True
        for ofmt in Image.known_vm_image_formats:
            if ofmt == ifmt:
                continue
            # Now Proceed to conversion
            timg = str(datadir.join("target-" + ifmt + "." + ofmt))
            Image.convert(simg, timg, overwrite=False, quiet=True)
            assert os.path.isfile(timg) is True
            # Conversion with LOGs
            timg = str(datadir.join("target2-" + ifmt + "." + ofmt))
            Image.convert(simg, timg, overwrite=False, quiet=False)
            assert os.path.isfile(timg) is True
            # Conversion with overwrite
            timg = str(datadir.join("target-" + ifmt + "." + ofmt))
            Image.convert(simg, timg, overwrite=True, quiet=True)
            assert os.path.isfile(timg) is True
            # Conversion do not overwrite
            timg = str(datadir.join("target-" + ifmt + "." + ofmt))
            assert os.path.isfile(timg) is True
            with pytest.raises(Exception):
                Image.convert(simg, timg)

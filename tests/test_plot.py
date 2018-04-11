import pytest
import os
import subprocess

from mock import patch

import pcocc.Plot as Plot


try:
    with open(os.devnull, 'w') as devnull:
        subprocess.call(["gnuplot", "--version"],
                        stdout=devnull,
                        stderr=devnull)
except OSError:
    pytest.skip("This test module needs gnuplot in the environment",
                allow_module_level=True)


def fake_term_size():
    return 100, 100


@patch("pcocc.Plot.terminal_size", side_effect=fake_term_size)
def test_plot_init_size(mock):
    # Basic from Term
    g = Plot.GnuPlot()
    assert g.row == 100
    assert g.col == 100
    del g
    # Manual
    g = Plot.GnuPlot(width=1000, height=10)
    assert g.row == 1000
    assert g.col == 10
    del g
    # Factor
    g = Plot.GnuPlot(factor=.5)
    assert g.row == 50
    assert g.col == 50
    del g
    # Factor and ratio
    g = Plot.GnuPlot(factor=.5, ratio=5)
    assert g.row == 10
    assert g.col == 50
    del g
    # Factor and ratio forced
    g = Plot.GnuPlot(width=1000, height=1000,
                     factor=.5, ratio=5)
    assert g.row == 100
    assert g.col == 500
    del g


@patch("pcocc.Plot.terminal_size", side_effect=fake_term_size)
def test_resize(mock):
    # Basic from Term
    g = Plot.GnuPlot()
    assert g.row == 100
    assert g.col == 100
    # Manual
    g.resize(width=1000, height=10)
    assert g.row == 1000
    assert g.col == 10
    # Factor
    g.resize(factor=.5)
    assert g.row == 50
    assert g.col == 50
    # Factor and ratio
    g.resize(factor=.5, ratio=5)
    assert g.row == 10
    assert g.col == 50
    # Factor and ratio forced
    g.resize(width=1000, height=1000,
                     factor=.5, ratio=5)
    assert g.row == 100
    assert g.col == 500


def no_gnuplot(*args, **kwargs):
    raise OSError


def failed_gnuplot(*args, **kwargs):
    raise subprocess.CalledProcessError(1,"Test")

@patch("subprocess.call", side_effect=no_gnuplot)
def test_no_gnuplot(mock):
    with pytest.raises(Exception):
        Plot.GnuPlot()


class FakePopen(object):
    def __init__(self):
        pass

    def read(self):
        return "123 456\n"


def fakestty(*args, **kwargs):
    fpo = FakePopen()
    return fpo


def fakesttyfail(*args, **kwargs):
    raise OSError


@patch("os.popen", side_effect=fakestty)
def test_term_size(mock):
    c, r = Plot.terminal_size()
    assert c == "123"
    assert r == "456"


@patch("os.popen", side_effect=fakesttyfail)
def test_term_size_fail(mock):
    c, r = Plot.terminal_size()
    assert c == "100"
    assert r == "100"


@patch("pcocc.Plot.terminal_size", side_effect=fake_term_size)
def test_plot(mock):
    # Basic Plot
    g = Plot.GnuPlot()
    d = [[[0, 1], [1, 1]]]
    t = ["test"]
    r = g.plot(d, t)
    assert r is True
    # Basic Plot with grid
    g = Plot.GnuPlot()
    d = [[[0, 1], [1, 1]]]
    t = ["test"]
    r = g.plot(d, t, grid=True)
    # Basic Plot with style
    g = Plot.GnuPlot()
    d = [[[0, 1], [1, 1]]]
    t = ["test"]
    r = g.plot(d, t, style="i")
    assert r is True
    # Multi Series Plot
    g = Plot.GnuPlot()
    d = [[[0, 1], [1, 1]], [[0, 1], [1, 1]]]
    t = ["test", "test2"]
    r = g.plot(d, t)
    assert r is True
    # Basic String
    g = Plot.GnuPlot()
    d = [[["0", "1"], ["1", "1"]]]
    t = ["test"]
    r = g.plot(d, t)
    assert r is True
    # Multi Series String Plot
    g = Plot.GnuPlot()
    d = [[["0", "1"], ["1", "1"]], [["0", "1"], ["1", "1"]]]
    t = ["test", "test2"]
    r = g.plot(d, t)
    assert r is True
    # Can Plot with Nones
    # Multi Series String Plot
    g = Plot.GnuPlot()
    d = [[["0", "1"], ["1", "1"]], None, [["0", "1"], ["1", "1"]]]
    t = ["test", None, "test2"]
    r = g.plot(d, t)
    assert r is True


@patch("pcocc.Plot.terminal_size", side_effect=fake_term_size)
def test_plot_fails(mock):
    g = Plot.GnuPlot()
    # No data
    with pytest.raises(Exception):
        g.plot(None, ["test"])
    # No titles
    dat = [[[0, 1], [1, 1]]]
    with pytest.raises(Exception):
        g.plot(dat, None)
    # Bad data
    with pytest.raises(Exception):
        g.plot({}, ["test"])
    # Bad point
    with pytest.raises(Exception):
        g.plot([[{}]], ["test"])
    # Bad serie
    with pytest.raises(Exception):
        g.plot([{"toto": [1, 2]}], ["test"])
    # No data
    assert g.plot([], ["test"]) is False
    # Title data mismatch
    with pytest.raises(Exception):
        g.plot(dat, ["test", "test2"])

@patch("pcocc.Plot.terminal_size", side_effect=fake_term_size)
def test_no_gnuplot_at_plot(mock):
    g = Plot.GnuPlot()
    dat = [[[0, 1], [1, 1]]]
    with patch("subprocess.call", side_effect=failed_gnuplot):
        with pytest.raises(Exception):
            g.plot(dat, ["test"])


def test_clear_screen():
    g = Plot.GnuPlot()
    g.clear_win()


import os
import logging
import tempfile
import subprocess


def terminal_size():
    try:
        row, col = os.popen('stty size', 'r').read().split()
    except:
        # Use defaults
        row, col = "100", "100",
    return row, col


class GnuPlot(object):

    def __init__(self, width=-1, height=-1, factor=1, ratio=None):
        self.factor = factor
        self.ratio = ratio
        self.resize(width, height)

        # Now do a quick check that Gnuplot is here
        try:
            with open(os.devnull, 'w') as devnull:
                subprocess.call(["gnuplot", "--version"],
                                stdout=devnull,
                                stderr=devnull)
        except OSError:
            raise Exception("GnuPlot was not found in your path")

    def resize(self, width=-1, height=-1, factor=None, ratio=None):
        if factor is None:
            factor = self.factor
        else:
            self.factor = factor
        if ratio is None:
            ratio = self.ratio
        if((width < 0) or (height < 0)):
            self.row, self.col = terminal_size()
            # Apply scale factor
            self.col = int(float(self.col) * self.factor)
            self.row = int(float(self.row) * self.factor)
            if ratio is not None:
                self.row = int(float(self.row) // ratio)
        else:
            self.row = width * self.factor
            self.col = height * self.factor
            if ratio is not None:
                self.row = int(float(self.row) // ratio)

    def clear_win(self):
        print(chr(27) + "[2J")

    def plot(self, data, titles=None, xlabel="", style="lp", grid=False):
        if data is None:
            raise Exception("No data provided to GnuPlot")
        if titles is None:
            raise Exception("No title provided to GnuPlot")
        if not isinstance(data, list):
            raise Exception("GnuPlot expects an array")

        if len(data) == 0:
            logging.error("No data to plot")
            return False

        if len(data) != len(titles):
            raise Exception("No title provided")

        # Filter nones
        data = filter(None, data)
        titles = filter(None, titles)

        # Handle term resize
        self.resize()

        # Extract all series in TMP files
        tmp_files = []

        for i in range(0, len(data)):
            tmp = tempfile.mktemp()
            serie = data[i]
            if not isinstance(serie, list):
                raise Exception("Series must be arrays of points")
            f = open(tmp, "w")
            for e in range(0, len(serie)):
                if not isinstance(serie[e], list) or (len(serie[e]) != 2):
                    raise Exception("Points have to be 2D arrays [0,1]")
                f.write("{0} {1}\n".format(serie[e][0], serie[e][1]))
            f.close()
            tmp_files.append(tmp)

        # Generate the GNUPLOT command
        gplot = "set terminal dumb size {0},{1} ansi256;".format(
            self.col,
            self.row
        )

        gplot = gplot + \
            "set key outside;"\
            "set xlabel \"{0}\";".format(xlabel)

        if grid:
            gplot = gplot + "set grid;"

        gdata = "plot "
        for i in range(0, len(tmp_files)):
            gdata = gdata + \
                " \"{0}\" using 1:2 w {1} title \"{2}\"".format(
                    tmp_files[i],
                    style,
                    titles[i]
                )
            if i != len(tmp_files) - 1:
                gdata = gdata + ","
            else:
                gdata = gdata + ";"

        gplot = gplot + gdata

        cmd = ["gnuplot", "-e", gplot]

        with open(os.devnull, 'w') as devnull:
            try:
                subprocess.call(cmd, stderr=devnull)
            except subprocess.CalledProcessError:
                raise Exception("An error occured when generating"
                                "the plot with Gnuplot")

        for f in tmp_files:
            os.remove(f)
        
        return True

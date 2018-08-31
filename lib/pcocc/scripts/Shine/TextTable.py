# Copyright or (c) or Copr. 2012, CEA
#
# This file is part of shine
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
# $Id$

"""
Table formatting classes for text-based interface.
"""

import re
import textwrap

COLORS = {
        'header': '\033[34m',
        'stop': '\033[0m',
    }

class TextTable(object):
    """
    Display a list of dict into a ASCII table, based an a printf-like format.

    >>> tbl = TextTable("%title %desc")
    >>> tbl.header_labels = {'desc': 'description'}
    >>> tbl.append({'title': "Winter hearts", 'desc': "A borring one"})
    >>> tbl.append({'title': "Storm gathering", 'desc': "Thrilling!"})
    >>> print tbl
    TITLE           DESCRIPTION
    -----           -----------
    Winter hearts   A borring one
    Storm gathering Thrilling!
    >>>

    It support header display, field place holder and aliases.
    Column are kept aligned base on the larger value or header name.

    Behaviour properties:
        ignore_bad_keys   Unknown key are displayed as-is (default: False)
        aliases           Dictionnary of aliases for format keys.

    Display properties:
        fmt               Format used to display each row and header.
        show_header       If True, display a uppercase header a the top of
                          the table (default: True)
        header_labels     Mapping of key to header text.
                          Default is to use the key as the header value.
        color             if True, displays table using colors.
        title             A title to display on top of the table
        optional_cols     Column list to not display if they are empty.
    """

    RE_PATTERN = "%(>)?(\d+)?(?P<name>[a-z]+)"

    def __init__(self, fmt=""):
        self._rows = []
        self._max_width = {}
        self._non_empty_cols = set()

        # Behavior
        self.ignore_bad_keys = False
        self.aliases = {}

        # Display control
        self.fmt = fmt
        self.show_header = True
        self.header_labels = {}
        self.col_width = {}
        self.color = False
        self.title = None
        self.optional_cols = []

    def __iter__(self):
        return iter(self._rows)

    def __len__(self):
        return len(self._rows)

    def _header(self, name):
        """
        Get the header string for the specified field name.

        The value is read in `header_labels' dict or `name' is used as-is if
        not present.
        """
        return self.header_labels.get(name, name)

    def _col_width(self, name):
        return self.col_width.get(name, 0)

    def pattern_fields(self):
        """Return the list of all field place holder name used in fmt.  """
        return [ match.group('name')
                 for match in re.finditer(self.RE_PATTERN, self.fmt) ]

    def purge(self):
        self._rows = []

    def append(self, row):
        """Append a new row to be displayed. `row' should be a dict."""
        leftover={}
        has_leftover=False
        # Keep track of wider value for each field
        for key, value in row.iteritems():
            header_length = len(self._header(key))
            real_value_len = len(str(value or ''))


            if self._col_width(key) and real_value_len >  self._col_width(key):
                wrap=textwrap.wrap(value, self._col_width(key))
                leftover[key] = ' '.join(wrap[1:])
                row[key] = wrap[0]
                real_value_len = len(row[key])
                has_leftover = True
            else:
                leftover[key] = ""

            # Keep track of the wider value in each col (header or value)
            self._max_width[key] = max(self._max_width.get(key, header_length),
                                       real_value_len)


            # Keep track of cols with at least one non empty row
            if real_value_len > 0 and key not in self._non_empty_cols:
                self._non_empty_cols.add(key)

        self._rows.append(row)
        if has_leftover:
            self.append(leftover)

    def _str_common(self, getter):
        """Generic function to build a table row using the table properties."""

        def replacer(matchobj):
            """Helper method for re.sub() to replace a place-holder."""
            key = self.aliases.get(matchobj.group(3), matchobj.group(3))
            length = 0
            value = ""
            try:
                length = matchobj.group(2) or self._max_width[key]
                length = int(length)
                value = getter(key) or ""
            except KeyError, ex:
                if self.ignore_bad_keys:
                    value = "%%%s" % key
                    length = len(value)
                elif len(self) == 0:
                    value = key
                    length = len(value)
                else:
                    raise ex

            # Optional columns which are empty are simply skipped
            if key in self.optional_cols and key not in self._non_empty_cols:
                return ""

            # If the value is too long, cut it
            if len(value) > length:
                length = max(4, length)
                value = "%s..." % value[:length - 3]
            if matchobj.group(1):
                return "%*s   " % (length, value)
            else:
                return "%-*s   " % (length, value)

        replacement = re.sub(self.RE_PATTERN, replacer, self.fmt)

        return re.sub("%%", "%", replacement)

    def _str_header(self):
        """Build the header string"""
        headline = self._str_common(self._header).upper().rstrip()
        underline = re.sub("[^ ]", '-', headline)
        if self.color:
            headline = "%s%s%s" % (COLORS['header'], headline, COLORS['stop'])
        if underline:
            headline = "%s\n%s" % (headline, underline)
        return headline

    def _str_row(self, row):
        """Build the string for the specified row (should be a dict)"""
        return self._str_common(row.__getitem__)

    def _str_title(self):
        """Build a title string"""
        width = len(self._str_common(self._header).rstrip())
        title = " %s " % self.title
        right = max((width - len(title)) / 2, 1)
        left = max(width - len(title) - right, 1)
        if self.color:
            title = "%s%s%s" % (COLORS['header'], title, COLORS['stop'])
        title = "%s%s%s" % ('=' * left, title, '=' * right)
        return title

    def __str__(self):
        output = []
        # Add header line if wanted
        if self.show_header:
            # Add title if defined
            if self.title:
                output.append(self._str_title())
            # Column headers
            output.append(self._str_header())
        # Then add each row
        for row in self:
            output.append(self._str_row(row).rstrip())

        return "\n".join(output)

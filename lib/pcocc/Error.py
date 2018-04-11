#  Copyright (C) 2014-2015 CEA/DAM/DIF
#
#  This file is part of PCOCC, a tool to easily create and deploy
#  virtual machines using the resource manager of a compute cluster.
#
#  PCOCC is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  PCOCC is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with PCOCC. If not, see <http://www.gnu.org/licenses/>

class PcoccError(Exception):
    """Base class for exceptions in this module."""
    def __init__(self, error):
        self.error = error
    def __str__(self):
        return self.error

class InvalidConfigurationError(PcoccError):
    """General class for syntax errors in the configuration files
    """
    def __init__(self, error):
        super(InvalidConfigurationError, self).__init__(
            'Unable to parse configuration file: ' + error)

class NoAgentError(PcoccError):
    """General class for syntax errors in the configuration files
    """
    def __init__(self):
        super(NoAgentError, self).__init__(
            "Could not contact the pcocc agent.\n"\
            "Make sure that your vm has started and that the agent is properly installed.")

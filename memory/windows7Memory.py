# -*- coding: utf-8 -*-
###############################################################################
#
#   FastResponder - Collect artefacts Windows for First Reponder
#	cert@sekoia.fr - http://www.sekoia.fr
#   Copyright (C) 2014  SEKOIA
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
###############################################################################

from __future__ import unicode_literals
from memory.mem import _Memory

class Windows7Memory(_Memory):
	def __init__(self, params):
		super(Windows7Memory, self).__init__(params)
	
	def csv_all_modules_dll(self):
		super(Windows7Memory, self)._csv_all_modules_dll()
	
	def csv_all_modules_opened_files(self):
		super(Windows7Memory, self)._csv_all_modules_opened_files()
	
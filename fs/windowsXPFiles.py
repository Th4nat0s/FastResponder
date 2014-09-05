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
from fs import _FS

class WindowsXPFiles(_FS):
	def __init__(self,params):
		super(WindowsXPFiles,self).__init__(params)
	
	def __list_named_pipes(self):
		return super(WindowsXPFiles,self)._list_named_pipes()
	
	def _list_windows_prefetch(self):
		return super(WindowsXPFiles,self)._list_windows_prefetch()		
	def csv_print_list_named_pipes(self):
		super(WindowsXPFiles,self). _csv_list_named_pipes(self._list_named_pipes())
		
	def csv_print_list_windows_prefetch(self):
		super(WindowsXPFiles,self)._csv_windows_prefetch(self._list_windows_prefetch())
	
	def csv_ie_history(self):
		super(WindowsXPFiles, self)._ie_history(['Local Settings\*\History.IE5'])

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
from registry.reg import _Reg

class Windows7UserReg(_Reg):
	def __init__(self, params):
		_Reg.__init__(self,params)
	
	def csv_open_save_MRU(self):
		super(Windows7UserReg, self)._csv_open_save_MRU('Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU\\')
	
	def csv_user_assist(self):
		super(Windows7UserReg, self)._csv_user_assist(0, True)
	
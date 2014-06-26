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
from _winreg import OpenKey, QueryInfoKey, EnumKey, CloseKey, HKEY_LOCAL_MACHINE
from utils import get_csv_writer

class WindowsAllHistoryUSB(_Reg):
	def __init__(self, params):
		_Reg.__init__(self, params)
		self.logger=params['logger']
	
	def _get_key_info(self, key_name):
		''' Extract information from the registry concerning the USB key '''
		#HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\DeviceClasses\{a5dcbf10-6530-11d2-901f-00c04fb951ed}
		str_reg_key_usbinfo = "SYSTEM\ControlSet001\Control\DeviceClasses\{a5dcbf10-6530-11d2-901f-00c04fb951ed}\\"
		
		# here is a sample of a key_name
		# ##?#USBSTOR#Disk&Ven_&Prod_USB_DISK_2.0&Rev_PMAP#07BC13025A3B03A1&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
		# the logic is : there are 6 '#' so we should split this string on '#' and get the USB id (index 5)
		index_id = 5
		usb_id = key_name.split('#')[index_id]
		# now we want only the left part of the which may contain another separator '&' -> 07BC13025A3B03A1&0
		usb_id = usb_id.split('&')[0]
		
		# next we look in the registry for such an id
		key_ids = ""
		reg_key_info = OpenKey(self.aReg, str_reg_key_usbinfo)
		for i in range(QueryInfoKey(reg_key_info)[0]): # the number of subkeys
			try:
				subkey_name=EnumKey(reg_key_info,i)
				if usb_id in subkey_name:
					# example of a key_info_name
					# ##?#USB#VID_26BD&PID_9917#0702313E309E0863#{a5dcbf10-6530-11d2-901f-00c04fb951ed}
					# the pattern is quite similar, a '#' separated string, with 5 as key id and 4 as VID&PID, we need those 2
					index_id = 4
					key_ids = subkey_name.split('#')[index_id]
					break
			except EnvironmentError:
				break
		CloseKey(reg_key_info)
		return key_ids
	
	def print_regkey_csv(self):
		self.logger.info('Getting USB history')
		key = 'SYSTEM\CurrentControlSet\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}\\'
		with open(self.output_dir + '\\' + self.computer_name + '_USBHistory.csv', 'wb') as output:
			csv_writer = get_csv_writer(output)
			super(WindowsAllHistoryUSB,self)._print_regkey_csv(key, HKEY_LOCAL_MACHINE, False, csv_writer,'USBSTOR', self._get_key_info)

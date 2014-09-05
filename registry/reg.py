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
import re
import codecs
from _winreg import ConnectRegistry, OpenKey, CloseKey, EnumKey, QueryInfoKey, EnumValue, REG_MULTI_SZ,\
					REG_SZ, REG_DWORD, REG_BINARY, HKEY_USERS, HKEY_LOCAL_MACHINE
from utils import 	get_int_from_reversed_string, str_sid2username, convert_windate, dosdate, get_csv_writer, write_to_csv
from win32con import REG_QWORD

class _Reg(object):
	def __init__(self,params):
		if params['output_dir'] and params['computer_name']:
			self.computer_name = params['computer_name']
			self.output_dir = params['output_dir']
		self.logger=params['logger']
	
	def _print_regkey_csv(self, key_path, hive, is_recursive, output, subkey_type_to_query=None, additional_info_function=None):
		''' Main method to print all the data retrieved in the registry to the output file '''
		''' additional_info_function is a function parameter, as it is needed in some cases... '''
		self.aReg = ConnectRegistry(None, hive)
		try:
			bKey = OpenKey(self.aReg, key_path)
			self.__print_regkey_csv(bKey, key_path, output, is_recursive, subkey_type_to_query, additional_info_function)
			CloseKey(bKey)
		except WindowsError:
			self.logger.warn('Error while printing registry values.')
			return
	
	def __print_regkey_csv(self, bKey, key_path, csv_writer, is_recursive, subkey_type_to_query, additional_info_function):
		''' Recursive method that will parse the registry and write in the output file '''
		''' The subkey_type_to_query is a string that will be checked against the subkeys name if it is not None '''
		for i in range(QueryInfoKey(bKey)[0]):
			try:
				subkey_name=EnumKey(bKey,i)
				if subkey_type_to_query is None or subkey_type_to_query in subkey_name:
					# if it is None, then we go inside no matter what, else we check if it is in the name
					key_info = ''
					if additional_info_function:
						# this function is a parameter, it is None by default
						key_info = additional_info_function(subkey_name)
					subkey=OpenKey(bKey,subkey_name)
					subkey_path = key_path + subkey_name + '\\'
					node_type = 'Key'
					date_last_mod = convert_windate(QueryInfoKey(subkey)[2])
					#self.logger.info(date_last_mod + ' : ' + subkey_name)
					write_to_csv([self.computer_name, date_last_mod, 'HKEY_LOCAL_MACHINE', subkey_path, node_type, key_info], csv_writer)
					if is_recursive:
						self.__print_regkey_values_csv(subkey, date_last_mod, 'HKEY_LOCAL_MACHINE', subkey_path, csv_writer, is_recursive, subkey_type_to_query) # print the values first
						self.__print_regkey_csv(subkey, subkey_path, csv_writer) # and then go deeper in the tree
			except EnvironmentError:
				break
	
	def __print_regkey_values_csv(self, bKey, date_last_mod, hive_name, key_path, csv_writer, additional_data=None, optional_function=None):
		''' Get the registry values and write those in the output file '''
		for i in range(QueryInfoKey(bKey)[1]): # the number of values
			try:
				value_name=EnumValue(bKey,i)
				subkey_path = key_path + value_name[0].replace(b'\xa0', b' ')
				node_type = ''
				values = []
				if value_name[2] == REG_MULTI_SZ: # the value is a list
					node_type = 'REG_MULTI_SZ'
					values += value_name[1] # concat both lists
				elif value_name[2] == REG_QWORD: # the value is a list
					node_type = 'REG_QWORD'
					hex_str = '0x'
					for c in value_name[1]:
						hex_str += c.encode('hex') 
					values.append(hex_str) # get hexadecimal from string
				elif value_name[2] == REG_BINARY:
					node_type = 'REG_BINARY'
					if optional_function:
						res = optional_function(value_name[0], value_name[1])
						if res:
							values += res
					else:
						values.append('')
				else:
					if value_name[2] == REG_SZ:
						node_type = 'REG_SZ'
					elif value_name[2] == REG_DWORD:
						node_type = 'REG_DWORD'
					values.append(unicode(value_name[1])) # just add the element to the list
				for value in values:
					'''if node_type != 'REG_BINARY':
						value_tmp = value.replace('","', '_')
					else:
						value_tmp = value'''
					if isinstance(value, list):
						# we want to concat list for the csv, so if it is not a list, put it in a list...
						value_tmp = value
					else:
						value_tmp = [value]
					if additional_data:
						arr_output = [self.computer_name, additional_data, date_last_mod, hive_name+'\\'+subkey_path, node_type] + value_tmp
						write_to_csv(arr_output, csv_writer)
					else:
						write_to_csv([self.computer_name, date_last_mod, hive_name+'\\'+subkey_path, node_type] + value_tmp, csv_writer)
			except EnvironmentError:
				break
	
	def _dump_csv_registry_to_output(self, hive_name, path, hive, csv_writer, username=None, optional_function=None, is_recursive=True):
		''' Dumps the registry in the given output file object
			Path should end with the '\' (for concat reasons) '''
		try:
			reg_key = OpenKey(hive, path)
			# print values from key
			date_last_mod = convert_windate(QueryInfoKey(reg_key)[2])
			self.__print_regkey_values_csv(reg_key, date_last_mod, hive_name, path, csv_writer, username, optional_function)
			if is_recursive:
				for index_subkey in range(QueryInfoKey(reg_key)[0]): # the number of subkeys
					# then go further in the tree
					str_subkey = EnumKey(reg_key, index_subkey)
					self._dump_csv_registry_to_output(hive_name, path + str_subkey + '\\', hive, csv_writer, username, optional_function)
				CloseKey(reg_key)
		except WindowsError as e:
			if e.winerror == 5: # Access denied
				pass
			else:
				raise e
	
	def __construct_itempos_list(self, data):
		invalid_shitem_len = 0x14
		list_itempos = []
		tmp_data = data
		while True:
			try:
				if tmp_data[0:2] == b'\x14\x00': # invalid SHITEM entry
					tmp_data = tmp_data[invalid_shitem_len + 8:] # padding
					continue
				itempos_size = get_int_from_reversed_string(tmp_data[0:2])
				if itempos_size == 0:
					break
				list_itempos.append(tmp_data[:itempos_size])
				tmp_data = tmp_data[itempos_size:]
				# padding
				tmp_data = tmp_data[8:]
			except:
				break
		return list_itempos
	
	def __decode_itempos(self, itempos):
		# TODO understand the data structure more in depth
		tmp_data = itempos
		# itempos size
		itempos_size = get_int_from_reversed_string(tmp_data[0:2])
		tmp_data = tmp_data[2:]
		# padding
		tmp_data = tmp_data[2:]
		# filesize
		filesize = get_int_from_reversed_string(tmp_data[0:4])
		tmp_data = tmp_data[4:]
		# timestamp
		timestamp_modified_date = tmp_data[0:2]
		tmp_data = tmp_data[2:]
		timestamp_modified_time = tmp_data[0:2]
		tmp_data = tmp_data[2:]
		timestamp_modified = dosdate(timestamp_modified_date, timestamp_modified_time).strftime('%d/%m/%Y %H:%M:%S')
		# padding
		tmp_data = tmp_data[2:]
		# filename
		filename = ''
		for i in range(len(tmp_data)):
			if ord(tmp_data[i]) == 0: # NULL byte
				filename = tmp_data[0:i+1]
				tmp_data = tmp_data[i+1:]
				break
		# padding, it seems the next data will be following bytes "EF BE"
		for i in range(len(tmp_data)-1):
			if ord(tmp_data[i])==0xef and ord(tmp_data[i+1])==0xbe:
				try:
					tmp_data = tmp_data[i+2:]
					break
				except:
					self.logger.error('Error in shellbag data format')
					exit(1)
		# timestamp created
		timestamp_created_date = tmp_data[0:2]
		tmp_data = tmp_data[2:]
		timestamp_created_time = tmp_data[0:2]
		tmp_data = tmp_data[2:]
		timestamp_created = dosdate(timestamp_created_date, timestamp_created_time).strftime('%d/%m/%Y %H:%M:%S')
		# timestamp modified
		timestamp_access_date = tmp_data[0:2]
		tmp_data = tmp_data[2:]
		timestamp_access_time = tmp_data[0:2]
		tmp_data = tmp_data[2:]
		timestamp_access = dosdate(timestamp_access_date, timestamp_access_time).strftime('%d/%m/%Y %H:%M:%S')
		# big padding, I don't know what it is meant to represent, but it seems to be there constantly
		tmp_arr = tmp_data.split(15*b'\x00')
		if len(tmp_arr) >= 2:
			tmp_data = tmp_arr[1]
		else:
			tmp_data = ''
		# unicode string
		uni_filename = ''
		for i in range(len(tmp_data)/2):
			if (2*i)+1 >= len(tmp_data):
				break
			if tmp_data[2*i] == b'\x00' and tmp_data[(2*i)+1] == b'\x00':
				uni_filename = tmp_data[:2*(i+1)].decode('utf-16')
				tmp_data = tmp_data[2*(i+1):]
				break
		#return '"itempos_size:' + unicode(itempos_size) + '"|"filesize:' + unicode(filesize) + '"|"time modified:' + timestamp_modified + '"|"filename:' + filename + '"|"time created:' + timestamp_created + '"|"time accessed:' + timestamp_access + '"|"unicode filename:' + uni_filename + '"'
		return [unicode(itempos_size), unicode(filesize), timestamp_modified, filename, timestamp_created, timestamp_access, uni_filename]
	
	def __decode_shellbag_itempos_data(self, value_name, data):
		if 'ItemPos' in value_name:
			header_len = 0x10
			unknown_padding_len = 0x8
			tmp_data = data[header_len + unknown_padding_len:]
			list_itempos = self.__construct_itempos_list(tmp_data)
			list_itempos_printable = []
			for itempos in list_itempos:
				list_itempos_printable.append(self.__decode_itempos(itempos))
			return list_itempos_printable
	
	def __csv_user_assist_value_decode_before_win7(self, str_value_datatmp, count_offset):
		# the Count registry contains values representing the programs
		# each value is separated as :
		# first 4 bytes are session
		# following 4 bytes are number of times the program has been run
		# next 8 bytes are the timestamp of last execution
		# each of those values are in big endian which have to be converted in little endian
		
		# 16 bytes data
		str_value_data_session = str_value_datatmp[0:4]
		str_value_data_session = unicode(get_int_from_reversed_string(str_value_data_session))
		str_value_data_count = str_value_datatmp[4:8]
		str_value_data_count = unicode(get_int_from_reversed_string(str_value_data_count) + count_offset + 1)
		str_value_data_timestamp = str_value_datatmp[8:16]
		try:
			timestamp = get_int_from_reversed_string(str_value_data_timestamp)
			date_last_exec = convert_windate(timestamp)
		except ValueError:
			date_last_exec = None
		arr_data = [str_value_data_session, str_value_data_count]
		if date_last_exec:
			arr_data.append(date_last_exec)
		return arr_data
	
	def __csv_user_assist_value_decode_win7_and_after(self, str_value_datatmp, count_offset):
		''' The value in user assist has changed since Win7. It is taken into account here. '''
		# 16 bytes data
		str_value_data_session = str_value_datatmp[0:4]
		str_value_data_session = unicode(get_int_from_reversed_string(str_value_data_session))
		str_value_data_count = str_value_datatmp[4:8]
		str_value_data_count = unicode(get_int_from_reversed_string(str_value_data_count) + count_offset + 1)
		str_value_data_focus = str_value_datatmp[12:16]
		str_value_data_focus = unicode(get_int_from_reversed_string(str_value_data_focus))
		str_value_data_timestamp = str_value_datatmp[60:68]
		try:
			timestamp = get_int_from_reversed_string(str_value_data_timestamp)
			date_last_exec = convert_windate(timestamp)
		except ValueError:
			date_last_exec = None
		arr_data = [str_value_data_session, str_value_data_count, str_value_data_focus]
		if date_last_exec:
			arr_data.append(date_last_exec)
		return arr_data
	
	def _csv_user_assist(self, count_offset, is_win7_or_further):
		''' Extracts information from UserAssist registry key which contains information about executed programs '''
		''' The count offset is for Windows versions before 7, where it would start at 6... '''
		self.logger.info('Getting user_assist from registry')
		aReg = ConnectRegistry(None,HKEY_USERS)
		
		str_user_assist = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\'
		with open(self.output_dir + '\\' + self.computer_name + '_userassist.csv', 'wb') as output:
			csv_writer = get_csv_writer(output)
			for index_sid in range(QueryInfoKey(aReg)[0]): # the number of subkeys
				# in HKEY_USERS, we have a list of subkeys which are SIDs
				str_sid = EnumKey(aReg, index_sid)
				try:
					path = str_sid + '\\' + str_user_assist
					username = str_sid2username(str_sid)
					reg_user_assist = OpenKey(aReg, path)
					for index_clsid in range(QueryInfoKey(reg_user_assist)[0]): # the number of subkeys
						# in UserAssist, we have a list of IDs which may vary between different Windows versions
						str_clsid = EnumKey(reg_user_assist, index_clsid)
						result = [username, str_sid, str_clsid]
						reg_count = OpenKey(aReg, path + str_clsid + '\\Count')
						date_last_mod = convert_windate(QueryInfoKey(reg_count)[2])
						for index_value in range(QueryInfoKey(reg_count)[1]): # the number of values
							# the name of the value is encoded with ROT13
							str_value_name = EnumValue(reg_count, index_value)[0]
							str_value_name = codecs.decode(str_value_name, 'rot_13')
							str_value_datatmp = EnumValue(reg_count, index_value)[1]
							# some data are less than 16 bytes for some reason...
							if len(str_value_datatmp) < 16:
								write_to_csv(result + [str_value_name, date_last_mod], csv_writer)
							else:
								if is_win7_or_further:
									arr_output = result + [str_value_name, date_last_mod] + self.__csv_user_assist_value_decode_win7_and_after(str_value_datatmp, count_offset)
									write_to_csv(arr_output, csv_writer)
								else:
									write_to_csv(result + [str_value_name, date_last_mod] + self.__csv_user_assist_value_decode_before_win7(str_value_datatmp, count_offset), csv_writer) 
						CloseKey(reg_count)
					CloseKey(reg_user_assist)
				except WindowsError:
					pass
			CloseKey(aReg)
	
	def __extract_filename_from_PIDLMRU(self, str_mru):
		#l = value_filetype[1].split('\x00\x00')
		l = []
		last_sep = 0
		# Split function, it will split only every 2 bytes
		for i in range(len(str_mru)/2):
			if (2*i)+1 >= len(str_mru): break
			if str_mru[2*i] == b'\x00' and str_mru[(2*i)+1] == b'\x00':
				l.append(str_mru[last_sep:2*i])
				last_sep=2*(i+1)
		l_printable = []
		for item in l:
			try:
				item_tmp = item.decode('utf-16')
				if re.match('.+\..+', item_tmp):
					l_printable.append(item_tmp)
			except:
				pass
		return l_printable
	
	def _csv_open_save_MRU(self, str_opensaveMRU):
		''' Extracts information from OpenSaveMRU registry key which contains information about opened and saved windows '''
		# TODO : Win XP
		self.logger.info('Getting open_save_MRU from registry')
		aReg = ConnectRegistry(None,HKEY_USERS)
		
		with open(self.output_dir + '\\' + self.computer_name + '_opensaveMRU.csv', 'wb') as output:
			csv_writer = get_csv_writer(output)
			for index_sid in range(QueryInfoKey(aReg)[0]): # the number of subkeys
				# in HKEY_USERS, we have a list of subkeys which are SIDs
				str_sid = EnumKey(aReg, index_sid)
				try:
					username = str_sid2username(str_sid)
					path = str_sid + '\\' + str_opensaveMRU
					reg_opensaveMRU = OpenKey(aReg, path)
					for index_clsid in range(QueryInfoKey(reg_opensaveMRU)[0]): # the number of subkeys
						str_filetype = EnumKey(reg_opensaveMRU, index_clsid)
						reg_filetype = OpenKey(aReg, path + '\\' + str_filetype)
						date_last_mod = convert_windate(QueryInfoKey(reg_filetype)[2])
						# now get the value from the SID subkey
						for index_value in range(QueryInfoKey(reg_filetype)[1]): # the number of values
							value_filetype = EnumValue(reg_filetype, index_value)
							# Here, it is quite... dirty, it is a binary MRU list in which we have to extract the interesting values
							if value_filetype[0] != 'MRUListEx':
								l_printable = self.__extract_filename_from_PIDLMRU(value_filetype[1])
								
								# VERY DIRTY, if the list is empty it's probably because the string is off by 1...
								if len(l_printable) == 0:
									# So we take away the first char to have a correct offset (modulo 2)
									l_printable = self.__extract_filename_from_PIDLMRU(value_filetype[1][1:])
								if len(l_printable) != 0:
									str_printable = l_printable[-1]
									write_to_csv([username, str_sid, str_filetype, date_last_mod, str_printable], csv_writer)
								else: # if the length is still 0 then... I'm at a loss for words
									write_to_csv([username, str_sid, str_filetype, date_last_mod], csv_writer)
						CloseKey(reg_filetype)
					CloseKey(reg_opensaveMRU)
				except WindowsError:
					pass
		CloseKey(aReg)

	def csv_registry_services(self):
		self.logger.info('Getting services from registry')
		aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
		with open(self.output_dir + '\\' + self.computer_name + '_services_registry.csv', 'wb') as output:
			csv_writer = get_csv_writer(output)
			try:
				#write_to_output('"Computer Name""|""CatchEvidence""|""Date last modification""|""Registry path""|""Registry type""|""Value"', output)
				self._dump_csv_registry_to_output('HKEY_LOCAL_MACHINE', 'System\CurrentControlSet\Services\\', aReg, csv_writer)
			except WindowsError:
				pass
		CloseKey(aReg)
	
	def __decode_recent_docs_MRU(self, value):
		# Decodes recent docs MRU list
		# Returns an array with 1st element being the filename, the second element being the symbolic link name
		value_decoded = []
		if b'\x00\x00\x00' in value:
			index = value.find(b'\x00\x00\x00')
			value_decoded.append(value[0:index+1].decode('utf-16-le'))
			index_end_link_name = value.find(b'\x00', index+3 + 14) # index+3 because the last char also ends with \x00 + null bytes \x00\x00, +14 is the offset for the link name
			value_decoded.append(value[index+3+14:index_end_link_name])
		return value_decoded
	
	def csv_recent_docs(self):
		# Shows where recently opened files are saved and when they were opened
		self.logger.info('Getting recent_docs from registry')
		path = '\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\\'
		aReg = ConnectRegistry(None,HKEY_USERS)
		with open(self.output_dir + '\\' + self.computer_name + '_recent_docs.csv', 'wb') as output:
			csv_writer = get_csv_writer(output)
			for index_sid in range(QueryInfoKey(aReg)[0]): # the number of subkeys (SIDs)
				str_sid = EnumKey(aReg, index_sid)
				full_path = str_sid + path
				try:
					username = str_sid2username(str_sid)
					result = [username, str_sid]
					reg_recent_docs = OpenKey(aReg, full_path)
					# Get values of RecentDocs itself
					for index_value in range(QueryInfoKey(reg_recent_docs)[1]): # the number of values (RecentDocs)
						str_value_name = EnumValue(reg_recent_docs, index_value)[0]
						str_value_datatmp = EnumValue(reg_recent_docs, index_value)[1]
						if str_value_name != "MRUListEx":
							value_decoded = self.__decode_recent_docs_MRU(str_value_datatmp)
							write_to_csv(result + value_decoded, csv_writer)
					# Get values of RecentDocs subkeys
					for index_recent_docs_subkey in range(QueryInfoKey(reg_recent_docs)[0]): # the number of subkeys (RecentDocs)
						recent_docs_subkey = EnumKey(reg_recent_docs, index_recent_docs_subkey)
						reg_recent_docs_subkey = OpenKey(aReg, full_path + recent_docs_subkey)
						for index_value in range(QueryInfoKey(reg_recent_docs_subkey)[1]): # the number of values (RecentDocs subkeys)
							str_value_name = EnumValue(reg_recent_docs_subkey, index_value)[0]
							str_value_datatmp = EnumValue(reg_recent_docs_subkey, index_value)[1]
							if str_value_name != "MRUListEx":
								value_decoded = self.__decode_recent_docs_MRU(str_value_datatmp)
								write_to_csv(result + value_decoded, csv_writer)
					#self._dump_csv_registry_to_output('HKEY_USERS', full_path, aReg, csv_writer, username)
				except WindowsError:
					pass
		CloseKey(aReg)
	
	def csv_installer_folder(self):
		# Shows where recently opened files are saved and when they were opened
		self.logger.info('Getting installer folders from registry')
		path = 'Software\Microsoft\Windows\CurrentVersion\Installer\Folders\\'
		with open(self.output_dir + '\\' + self.computer_name + '_installer_folder.csv', 'ab') as output:
			aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
			csv_writer = get_csv_writer(output)
			try:
				self._dump_csv_registry_to_output('HKEY_LOCAL_MACHINE', path, aReg, csv_writer)
			except WindowsError:
				pass
		CloseKey(aReg)
	
	def csv_shell_bags(self):
		''' Exports the shell bags from Windows registry in a csv '''
		# TODO Check Vista and under
		self.logger.info("Getting shell bags from registry")
		aReg = ConnectRegistry(None,HKEY_USERS)
		with open(self.output_dir + '\\' + self.computer_name + '_shellbags.csv', 'wb') as output:
			csv_writer = get_csv_writer(output)
			for index_sid in range(QueryInfoKey(aReg)[0]): # the number of subkeys
				# in HKEY_USERS, we have a list of subkeys which are SIDs
				str_sid = EnumKey(aReg, index_sid)
				username = str_sid2username(str_sid)
				paths = ['\\Software\\Microsoft\\Windows\\Shell\\Bags\\', '\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\',
						'\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags\\',
						'\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\']
				for path in paths:
					try:
						full_path = str_sid + path
						self._dump_csv_registry_to_output('HKEY_USERS', full_path, aReg, csv_writer, username, self.__decode_shellbag_itempos_data)
					except WindowsError:
						pass
		CloseKey(aReg)
	
	def csv_startup_programs(self):
		''' Exports the programs running at startup '''
		''' [HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run]
			[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx]
			[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce]
			[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices]
			[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce]
			[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Userinit]
			[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run]
			
			[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
			[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnceEx]
			[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce]
			[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices]
			[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce]
			[HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows]
		'''
		self.logger.info("Getting startup programs from registry")
		software = '\Software'
		wow = '\Wow6432Node'
		with open(self.output_dir + '\\' + self.computer_name + '_startup.csv', 'wb') as output:
			csv_writer = get_csv_writer(output)
			aReg = ConnectRegistry(None, HKEY_USERS)
			for index_sid in range(QueryInfoKey(aReg)[0]): # the number of subkeys
				# in HKEY_USERS, we have a list of subkeys which are SIDs
				str_sid = EnumKey(aReg, index_sid)
				username = str_sid2username(str_sid)
				paths = ['\Microsoft\Windows\CurrentVersion\Run\\', '\Microsoft\Windows\CurrentVersion\RunOnce\\',
						'\Software\Microsoft\Windows\CurrentVersion\RunOnceEx',
						'\Microsoft\Windows\CurrentVersion\RunServices\\',
						'\Microsoft\Windows\CurrentVersion\RunServicesOnce\\',
						'\Microsoft\Windows NT\CurrentVersion\Winlogon\\Userinit\\']
				for path in paths:
					try:
						full_path = str_sid + software + path
						self._dump_csv_registry_to_output('HKEY_USERS', full_path, aReg, csv_writer, username)
						full_path = str_sid + software + wow + path
						self._dump_csv_registry_to_output('HKEY_USERS', full_path, aReg, csv_writer, username)
					except WindowsError:
						pass
			CloseKey(aReg)
		with open(self.output_dir + '\\' + self.computer_name + '_startup.csv', 'ab') as output:
			csv_writer = get_csv_writer(output)
			aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
			paths = ['\Microsoft\Windows\CurrentVersion\Run\\', '\Microsoft\Windows\CurrentVersion\RunOnce\\',
					'\Software\Microsoft\Windows\CurrentVersion\RunOnceEx',
					'\Microsoft\Windows\CurrentVersion\RunServices\\',
					'\Microsoft\Windows\CurrentVersion\RunServicesOnce\\',
					'\Microsoft\Windows NT\CurrentVersion\Windows\\',
					'\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run']
			for path in paths:
				try:
					full_path = software + path
					self._dump_csv_registry_to_output('HKEY_LOCAL_MACHINE', path, aReg, csv_writer)
					full_path = software + wow + path
					self._dump_csv_registry_to_output('HKEY_LOCAL_MACHINE', path, aReg, csv_writer)
				except WindowsError:
					pass
		CloseKey(aReg)
	
	def csv_installed_components(self):
		# outputs installed components to file
		''' HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components '''
		self.logger.info('Getting installed components from registry')
		path = 'Software\Microsoft\Active Setup\Installed Components\\'
		with open(self.output_dir + '\\' + self.computer_name + '_installed_components.csv', 'wb') as output:
			aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
			csv_writer = get_csv_writer(output)
			try:
				self._dump_csv_registry_to_output('HKEY_LOCAL_MACHINE', path, aReg, csv_writer)
			except WindowsError:
				pass
		CloseKey(aReg)
	
	def csv_winlogon_values(self):
		# outputs winlogon's values to file
		self.logger.info('Getting winlogon values from registry')
		path = 'Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\'
		with open(self.output_dir + '\\' + self.computer_name + '_winlogon_values.csv', 'wb') as output:
			aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
			csv_writer = get_csv_writer(output)
			try:
				self._dump_csv_registry_to_output('HKEY_LOCAL_MACHINE', path, aReg, csv_writer, is_recursive=False)
				aReg = ConnectRegistry(None, HKEY_USERS)
				for index_sid in range(QueryInfoKey(aReg)[0]): # the number of subkeys
					# in HKEY_USERS, we have a list of subkeys which are SIDs
					str_sid = EnumKey(aReg, index_sid)
					username = str_sid2username(str_sid)
					full_path = str_sid + '\\' + path
					try:
						self._dump_csv_registry_to_output('HKEY_USERS', full_path, aReg, csv_writer, username, is_recursive=False)
					except WindowsError:
						pass
			except WindowsError:
				pass
		CloseKey(aReg)
	
	def csv_windows_values(self):
		# outputs winlogon's values to file
		self.logger.info('Getting windows values from registry')
		path = 'Software\Microsoft\Windows NT\CurrentVersion\Windows\\'
		with open(self.output_dir + '\\' + self.computer_name + '_windows_values.csv', 'wb') as output:
			aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
			csv_writer = get_csv_writer(output)
			try:
				self._dump_csv_registry_to_output('HKEY_LOCAL_MACHINE', path, aReg, csv_writer, is_recursive=False)
				aReg = ConnectRegistry(None, HKEY_USERS)
				for index_sid in range(QueryInfoKey(aReg)[0]): # the number of subkeys
					# in HKEY_USERS, we have a list of subkeys which are SIDs
					str_sid = EnumKey(aReg, index_sid)
					username = str_sid2username(str_sid)
					full_path = str_sid + '\\' + path
					try:
						self._dump_csv_registry_to_output('HKEY_USERS', full_path, aReg, csv_writer, username, is_recursive=False)
					except WindowsError:
						pass
			except WindowsError:
				pass
		CloseKey(aReg)
		
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
	
	def csv_usb_history(self):
		self.logger.info('Getting USB history')
		key = 'SYSTEM\CurrentControlSet\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}\\'
		with open(self.output_dir + '\\' + self.computer_name + '_USBHistory.csv', 'wb') as output:
			csv_writer = get_csv_writer(output)
			self._print_regkey_csv(key, HKEY_LOCAL_MACHINE, False, csv_writer,'USBSTOR', self._get_key_info)
	
	def run_mru_start(self):
		#TODO
		pass
	
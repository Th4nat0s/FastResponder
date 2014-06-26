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

import datetime
import logging
import os
import traceback
from utils import 	get_int_from_reversed_string, look_for_outlook_dirs, get_userprofiles_from_reg,\
					look_for_files, zip_archive, get_csv_writer, write_to_csv
from win32com.shell import shell, shellcon


class _FS(object):
	def __init__(self,params):
		self.userprofiles=None
		self.public=None
		self.systemroot=params['system_root']
		self.computer_name=params['computer_name']
		self.output_dir=params['output_dir']
		self.logger=params['logger']
		
	def _list_named_pipes(self):
		for p in look_for_files('\\\\.\\pipe\\*'):
			yield p
	
				
	def _list_windows_prefetch(self):
		''' Outputs windows prefetch files in a csv '''
		''' See http://www.forensicswiki.org/wiki/Windows_Prefetch_File_Format '''
		prefetch_path =self.systemroot + '\Prefetch\*.pf'
		list_prefetch_files = look_for_files(prefetch_path)
		
		
		for prefetch_file in list_prefetch_files:
			offset = 0
			content = ''
			with open(prefetch_file, 'rb') as file_input:
				content = file_input.read()
			try:
				format_version = content[:4]
				format_version = get_int_from_reversed_string(format_version)
				content = content[4:]
				offset += 4
				#scca_sig = content[:4]
				content = content[4:]
				offset += 4
				unknown_values = content[:4]
				unknown_values = ' '.join(c.encode('hex') for c in unknown_values)
				content = content[4:]
				offset += 4
				file_size = content[:4]
				file_size = get_int_from_reversed_string(file_size)
				content = content[4:]
				offset += 4
				exec_name = content[:60]
				for i in range(30): # 60 / 2
					if 2*i+1 < len(exec_name):
						if exec_name[2*i]=='\x00' and exec_name[2*i+1]=='\x00':
							exec_name = exec_name[:2*(i+1)].decode('utf-16-le')
				content = content[60:]
				offset += 60
				'''prefetch_hash = content[:4]
				content = content[4:]
				unknown_flag = content[:4]
				content = content[4:]'''
				content = content[8:] # prefetch hash, unknown
				tc=os.path.getctime(prefetch_file)
				tm=os.path.getmtime(prefetch_file)
				if format_version == 17:
					content = content[9*4:] # skip unknown sections
					latest_exec_date = content[:8]
					content = content[8:]
					content = content[16:] # unknown
					exec_count = get_int_from_reversed_string(content[:4])
					content = content[4:]
				elif format_version == 23:
					content = content[11*4:] # skip unknown sections
					offset += 11*4
					latest_exec_date = content[:8]
					content = content[8:]
					offset += 8
					content = content[16:] # unknown
					offset += 16
					exec_count = get_int_from_reversed_string(content[:4])
					content = content[4:]
				else:
					# format version 26
					content = content[11*4:] # skip unknown sections
					latest_exec_date = []
					for i in range(8):
						latest_exec_date.append(content[:8])
						content = content[8:]
					content = content[16:] # unknown
					exec_count = get_int_from_reversed_string(content[:4])
					content = content[4:]
				yield prefetch_file,format_version,file_size, exec_name, datetime.datetime.fromtimestamp(tc),datetime.datetime.fromtimestamp(tm), exec_count
			except:
				logging.error(traceback.format_exc())
	

	def _csv_list_named_pipes(self,pipes):
		with open(self.output_dir + '\\' + self.computer_name + '_named_pipes.csv', 'wb') as output:
			csv_writer = get_csv_writer(output)
			#output.write('"Computer Name"|"Type"|"Name"\n')
			for pipe in pipes:
				write_to_csv([self.computer_name, 'PIPES', pipe], csv_writer)
	
	def _csv_windows_prefetch(self,wpref):
		with open(self.output_dir + '\\' + self.computer_name + '_prefetch.csv', 'wb') as output:
			csv_writer = get_csv_writer(output)
			#output.write('"Computer Name"|"Type"|"File"|"Version"|"Size"|"name Exec"|"Create Time"|"Modification Time"\n')
			for prefetch_file, format_version, file_size, exec_name, tc, tm, run_count in wpref:
				write_to_csv([	self.computer_name, 'Prefetch', prefetch_file,
									unicode(format_version), unicode(file_size), exec_name.replace('\00', ''),
									unicode(tc), unicode(tm), unicode(run_count)], csv_writer)
	
	def __enum_directory(self, path):
		files_list = []
		for dirname, subdirnames, filenames in os.walk(path):
			for subdirname in subdirnames:
				files_list.append(os.path.join(dirname, subdirname))
			for filename in filenames:
				files_list.append(os.path.join(dirname, filename))
		return files_list
	
	def __data_from_userprofile(self, zipname, directories_to_search):
		''' Retrieves data from userprofile. Creates a zip archive containing windows from the directories given in parameters. '''
		userprofiles = get_userprofiles_from_reg()
		# File mode is write and truncate for the first iteration, append after
		file_mode = 'w'
		for userprofile in userprofiles:
			for directory_to_search in directories_to_search:
				full_path = userprofile + '\\' + directory_to_search
				# construct the list of windows in the directory_to_search for the zip function
				list_directories = look_for_files(full_path)
				for directory in list_directories:
					list_files = self.__enum_directory(directory)
					zip_archive(list_files, self.output_dir, zipname, self.logger, file_mode)
					file_mode = 'a'
	
	def _ie_history(self, directories_to_search):
		self.__data_from_userprofile("IEHistory", directories_to_search)
		
	def csv_recycle_bin(self):
		''' Exports the filenames contained in the recycle bin '''
		with open(self.output_dir + '\\' + self.computer_name + '_recycle_bin.csv', 'wb') as output:
			csv_writer = get_csv_writer(output)
			#output.write('"Computer Name"|"Type"|"Name 1"|"Name 2"\n')
			idl = shell.SHGetSpecialFolderLocation(0, shellcon.CSIDL_BITBUCKET)
			desktop = shell.SHGetDesktopFolder()
			files = desktop.BindToObject(idl, None, shell.IID_IShellFolder)
			
			for bin_file in files:
				write_to_csv([	self.computer_name, 'Recycle Bin', files.GetDisplayNameOf(bin_file, shellcon.SHGDN_NORMAL),
								files.GetDisplayNameOf(bin_file, shellcon.SHGDN_FORPARSING)], csv_writer)

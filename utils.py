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
import win32wnet
import win32netcon
import win32api
import win32file
import win32security
import win32con
import win32service
import os, sys
import datetime
import glob
import hashlib
from string import ascii_uppercase
from _winreg import ConnectRegistry, OpenKey, QueryInfoKey, EnumKey, EnumValue, CloseKey, HKEY_LOCAL_MACHINE
import zipfile
import wmi
import shutil
import traceback
import csv, cStringIO, codecs

class UnicodeWriter:
	"""
	A CSV writer which will write rows to CSV file "f",
	which is encoded in the given encoding.
	"""

	def __init__(self, f, dialect=csv.excel, encoding="utf-8", **kwds):
		# Redirect output to a queue
		self.queue = cStringIO.StringIO()
		self.writer = csv.writer(self.queue, dialect=dialect, **kwds)
		self.stream = f
		self.encoder = codecs.getincrementalencoder(encoding)()

	def writerow(self, row):
		try:
			self.writer.writerow([s.encode("utf-8") if s else '' for s in row])
		except:
			traceback.print_exc()
		# Fetch UTF-8 output from the queue ...
		data = self.queue.getvalue()
		data = data.decode("utf-8")
		# ... and reencode it into the target encoding
		data = self.encoder.encode(data)
		# write to the target stream
		self.stream.write(data)
		# empty queue
		self.queue.truncate(0)

	def writerows(self, rows):
		for row in rows:
			self.writerow(row)

def decode_output_cmd(output):
	string_to_encode=''
	for i in output:
		if ord(i) <= 128:
			string_to_encode=string_to_encode+i
	return string_to_encode

def change_to_MKTime(seconds):
	'''Change time by QueryInfoKey to mktime.'''
	# Time difference is 134774 days = days from 1.1.1600 -> 31.12.1968
	diff = 11644473600
	seconds = seconds / pow(10, 7)
	mktime = seconds - diff
	return mktime

def convert_windate(timestamp):
	return datetime.datetime.fromtimestamp(change_to_MKTime(timestamp)).strftime('%d/%m/%Y %H:%M:%S')

def dosdate(dosdate, dostime):
	"""
	`dosdate`: 2 bytes, little endian.
	`dostime`: 2 bytes, little endian.
	returns: datetime.datetime or datetime.datetime.min on error
	"""
	try:
		t = ord(dosdate[1]) << 8
		t |= ord(dosdate[0])
		day = t & 0b0000000000011111
		month = (t & 0b0000000111100000) >> 5
		year = (t & 0b1111111000000000) >> 9
		year += 1980
	
		t = ord(dostime[1]) << 8
		t |= ord(dostime[0])
		sec = t & 0b0000000000011111
		sec *= 2
		minute = (t & 0b0000011111100000) >> 5
		hour = (t & 0b1111100000000000) >> 11
	
		return datetime.datetime(year, month, day, hour, minute, sec)
	except:
		return datetime.datetime.min

def convert_string_to_hex(string):
	return ''.join(c.encode('hex') for c in string)

def reverse_string(string_to_reverse):
	''' Mainly used for little and big endian conversion '''
	return ''.join(c.encode('hex') for c in reversed(string_to_reverse))

def get_int_from_reversed_string(reversed_string):
	''' Used for registry timestamp '''
	if reversed_string != b'':
		return int(reverse_string(reversed_string), 16)
	else:
		return 0

def get_local_drives():
	''' Returns a list containing letters from local drives '''
	drive_list = win32api.GetLogicalDriveStrings()
	drive_list = drive_list.split('\x00')[0:-1] # the last element is ''
	list_local_drives = []
	for letter in drive_list:
		if win32file.GetDriveType(letter) == win32file.DRIVE_FIXED:
			list_local_drives.append(letter)
		'''elif win32file.GetDriveType(letter) == win32file.DRIVE_FIXED:
			drive_type = "Fixed"
		elif win32file.GetDriveType(letter) == win32file.DRIVE_REMOVABLE:
			drive_type = "Removable"
		elif win32file.GetDriveType(letter) == win32file.DRIVE_RAMDISK:
			drive_type = "Ramdisk"
		elif win32file.GetDriveType(letter) == win32file.DRIVE_REMOTE:
			drive_type = "Remote"
		else:
			drive_type = "Something else"
		print letter, drive_type'''
	return list_local_drives

def get_removable_drives():
	''' Returns a list containing letters from removable drives '''
	drive_list = win32api.GetLogicalDriveStrings()
	drive_list = drive_list.split('\x00')[0:-1] # the last element is ''
	list_removable_drives = []
	for letter in drive_list:
		if win32file.GetDriveType(letter) == win32file.DRIVE_REMOVABLE:
			list_removable_drives.append(letter)
	return list_removable_drives

def sid2username(sid):
	''' Convert an object sid to a string account name '''
	account = win32security.LookupAccountSid(None, sid)
	return account[0]

def str_sid2username(str_sid):
	''' Convert a string sid to a string account name '''
	
	'''sid = win32security.LookupAccountName(None, "Sekoia")[0]
	print sid'''
	try:
		sid = win32security.ConvertStringSidToSid(str_sid)
		return sid2username(sid)
	except:
		return ""

def get_userprofiles_from_reg():
	''' Retrieves and returns the userprofiles from the registry '''
	# SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList contains a list of subkeys representing SIDs
	aReg = ConnectRegistry(None,HKEY_LOCAL_MACHINE)
	str_userprofiles = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\'
	reg_profile_list = OpenKey(aReg, str_userprofiles)
	list_profiles = []
	for index_sid in range(QueryInfoKey(reg_profile_list)[0]): # the number of subkeys
		sid = EnumKey(reg_profile_list, index_sid)
		reg_sid = OpenKey(aReg, str_userprofiles + sid)
		# now get the value from the SID subkey
		for index_value in range(QueryInfoKey(reg_sid)[1]): # the number of values
			value_sid = EnumValue(reg_sid, index_value)
			if value_sid[0] == 'ProfileImagePath':
				list_profiles.append(value_sid[1])
				break
		CloseKey(reg_sid)
	CloseKey(reg_profile_list)
	CloseKey(aReg)
	return list_profiles

def check_outlook_d(path):
	''' Checks the existence of the Outlook common filepath in the given path
		Returns the path if it exists, None otherwise '''
	application_data = path + '\\Local Settings\\Application Data\\Microsoft\\Outlook'
	if os.path.exists(application_data):
		return application_data
	appdata = path + '\\AppData\\Local\\Microsoft\\Outlook'
	if os.path.exists(appdata):
		return appdata
	return None

def look_for_outlook_dirs(paths_to_search):
	''' Takes a list of paths to search for Outlook, will return a list of valid Outlook paths
		A good practice is to take the output from get_userprofiles_from_reg() function
		Returns the path if it exists, None otherwise '''
	valid_paths = []
	if paths_to_search:
		for path in paths_to_search:
			path = check_outlook_d(path)
			if path:
				valid_paths.append(path)
	return valid_paths

def look_for_files(dir_to_look):
	''' Looks for windows in a given directory. Supports the * wildcard character '''
	found_files = []
	if '*' in dir_to_look:
		found_files += glob.glob(dir_to_look)
	elif os.path.exists(dir_to_look):
		found_files.append(dir_to_look)
	return found_files

def zip_from_object(files_to_zip, zip_object, logger):
	''' Zips a list of windows given the zip object '''
	for file_to_zip in files_to_zip:
		try:
			zip_object.write(file_to_zip)
		except OSError:
			logger.warn('file not found ' + file_to_zip)
		except IOError as err:
			if err.errno == 13: # Permission denied
				logger.warn('Permission denied for : ' + file_to_zip)

def zip_archive(files_to_zip, zip_path, filename, logger, file_mode='w'):
	''' Uses the global variable to save the zip file. Creates a zip archive containing windows given in parameters.
		The file mode is write by default. It can also be 'a' for append. '''
	computer_name = os.environ["COMPUTERNAME"]
	zip_fullname = zip_path + '\\' + computer_name + '_' + filename + '.zip'
	with zipfile.ZipFile(zip_fullname, file_mode) as myzip:
		zip_from_object(files_to_zip, myzip, logger)

def clean(path,computer_name):
	list_file_erase=glob.glob(path+'/'+computer_name+'*.csv')
	for l in list_file_erase:	
		os.remove(l)

def is_locked(filename):
	try:
		open(filename,'r').read(1)
		return False
	except:
		return True
		pass
	return False

def is_open(filename):
	handle=win32file.CreateFile(filename, win32file.GENERIC_READ, 0, None, win32file.OPEN_EXISTING, win32file.FILE_ATTRIBUTE_NORMAL, 0)
	if handle:
		return True
	else:
		return False

def is_allowed(filename):
	try:
		open(filename,'r').read(1)
		return True
	except IOError as e:
		errorcode, desc=e.args
		if errorcode==13:
			return False
		else:
			return True

def is_running(name):
	c = wmi.WMI ()
	service = c.Win32_Service (Name=name)[0]
	if service.State=="Running":
		return (service,True)
	else:
		return (service,False)
	
def copy_file(root,path,dest):
	try:
		dirs, f=os.path.split(dest+path.replace(root,''))
		os.makedirs(dirs)
		shutil.copy(path,dest+path.replace(root,''))
		return dest+path.replace(root,'')
	except WindowsError:
		pass
	
def checkPermissions(path, logger):
	logger.info("I am", win32api.GetUserNameEx (win32con.NameSamCompatible))
	logger.info(path)
	sd = win32security.GetFileSecurity (path, win32security.OWNER_SECURITY_INFORMATION)
	owner_sid = sd.GetSecurityDescriptorOwner ()
	name, domain, type = win32security.LookupAccountSid (None, owner_sid)
	
	logger.info("File owned by %s\\%s" % (domain, name))
	
def write_to_output(str_to_write, output, logger):
	''' Writes content to a file, encoding the string in UTF-8 for compatibility issues '''
	try:
		output.write(str_to_write.encode('utf-8'))
	except UnicodeError:
		logger.error(traceback.print_exc())

def get_terminal_decoded_string(string):
	return string.decode(sys.stdout.encoding)

def get_csv_writer(csvfile):
	return UnicodeWriter(csvfile, quoting=csv.QUOTE_ALL)

def write_to_csv(arr_data, csv_writer):
	''' Writes contents to a CSV file and encodes the array of strings in UTF-8 '''
	csv_writer.writerow(arr_data)

def get_architecture():
	if sys.maxsize > 2**32:
		return '64'
	else:
		return '86'

def process_size(size_str):
	unities={'k':1024L,'M':1024L*1024L,'G':1024L*1024L*1024L}
	suffix=size_str[len(size_str)-1:]
	value=size_str[:len(size_str)-1]
	return long(value)*unities[suffix]
	
def record_sha256_logs(fr,fw):
	with open(fw,'a') as hash_file:
		m=process_sha256(fr)
		hash_file.write(fr+','+m.hexdigest()+'\n')
		hash_file.close()
		
def process_sha256(path):
	f = open(path,'r')
	m = hashlib.md5()
	for chunck in f.read(8096):
		m.update(chunck)
	return m

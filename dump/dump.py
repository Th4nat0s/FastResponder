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

from StringIO import StringIO
import binascii
import os
import struct
import subprocess
import sys
import time
from disk_analysis import DiskAnalysis
from analyzemft.mftsession import _MftSession
from mbr import Mbr
from environment_settings import Partitions, Disks, OperatingSystem,\
	EnvironmentVariable
from settings import LONGLONGSIZE,BYTESIZE,WORDSIZE
from utils import 	get_local_drives
from utils_rawstring import decodeATRHeader, decodeDataRuns
import win32file


class _Dump(object):
	def __init__(self,params):
		self.computer_name=params['computer_name']
		self.output_dir=params['output_dir']
		self.logger=params['logger']
	
	def csv_mft(self):
		''' Exports the MFT from each local drives and creates a csv from it. '''
		local_drives = get_local_drives()
		for local_drive in local_drives:
			self.logger.info('Exporting MFT for drive : ' + local_drive)
			ntfsdrive=file('\\\\.\\' + local_drive.replace('\\', ''), 'rb')
			if os.name=='nt':
				#poor win can't seek a drive to individual bytes..only 1 sector at a time..
				#convert MBR to stringio to make it seekable
				ntfs=ntfsdrive.read(512)
				ntfsfile=StringIO(ntfs)
			else:
				ntfsfile=ntfsdrive
		
			#parse the MBR for this drive to get the bytes per sector,sectors per cluster and MFT location.
			#bytes per sector
			ntfsfile.seek(0x0b)
			bytesPerSector=ntfsfile.read(WORDSIZE)
			bytesPerSector=struct.unpack(b'<h', binascii.unhexlify(binascii.hexlify(bytesPerSector)))[0]
			
			#sectors per cluster
			
			ntfsfile.seek(0x0d)
			sectorsPerCluster=ntfsfile.read(BYTESIZE)
			sectorsPerCluster=struct.unpack(b'<b', binascii.unhexlify(binascii.hexlify(sectorsPerCluster)))[0]
			
			#get mftlogical cluster number
			ntfsfile.seek(0x30)
			cno=ntfsfile.read(LONGLONGSIZE)
			mftClusterNumber=struct.unpack(b'<q', binascii.unhexlify(binascii.hexlify(cno)))[0]
			
			#MFT is then at NTFS + (bytesPerSector*sectorsPerCluster*mftClusterNumber)
			mftloc=long(bytesPerSector*sectorsPerCluster*mftClusterNumber)
			ntfsdrive.seek(0)
			ntfsdrive.seek(mftloc)
			mftraw=ntfsdrive.read(1024)
			
			#We've got the MFT record for the MFT itself.
			#parse it to the DATA section, decode the data runs and send the MFT over TCP
			mftDict={}
			mftDict['attr_off'] = struct.unpack(b"<H",mftraw[20:22])[0]
			ReadPtr=mftDict['attr_off']
			with open(self.output_dir + '\\' + self.computer_name + '_mft_' + local_drive[0] + '.mft', 'wb') as output:
				while ReadPtr<len(mftraw):
					ATRrecord = decodeATRHeader(mftraw[ReadPtr:])
					if ATRrecord['type'] == 0x80:
						dataruns=mftraw[ReadPtr+ATRrecord['run_off']:ReadPtr+ATRrecord['len']]
						prevCluster=None
						prevSeek=0
						for length,cluster in decodeDataRuns(dataruns):
							if prevCluster==None:
								ntfsdrive.seek(cluster*bytesPerSector*sectorsPerCluster)
								prevSeek=ntfsdrive.tell()
								r_data = ntfsdrive.read(length*bytesPerSector*sectorsPerCluster)
								output.write(r_data)
								prevCluster=cluster
							else:
								ntfsdrive.seek(prevSeek)
								newpos=prevSeek + (cluster*bytesPerSector*sectorsPerCluster)
								ntfsdrive.seek(newpos)
								prevSeek=ntfsdrive.tell()
								r_data = ntfsdrive.read(length*bytesPerSector*sectorsPerCluster)
								output.write(r_data)
								prevCluster=cluster
						break
					if ATRrecord['len'] > 0:
						ReadPtr = ReadPtr + ATRrecord['len']
			session = _MftSession(self.logger, self.output_dir + '\\' + self.computer_name + '_mft_' + local_drive[0] + '.mft',
										self.output_dir + '\\' + self.computer_name + '_mft_' + local_drive[0] + '.csv')
			session.open_files()
			session.process_mft_file()	
	
	def csv_mbr(self):
		''' Extract MBR and BootLoader '''
		informations = DiskAnalysis(self.output_dir)
		partition = Partitions(self.output_dir,self.logger)
		disk = Disks()
		operatingSystem = OperatingSystem()
		envVar = EnvironmentVariable()
		mbr = Mbr(self.output_dir)
		informations.os = operatingSystem.os_informations(informations.currentMachine)
		informations.listDisks = disk.getDiskInformations(informations.currentMachine)
		self.logger.info('MBR Extracting')
		for d in informations.listDisks:
			informations.mbrDisk = mbr.mbr_parsing(d.deviceID)
			mbr.bootLoaderDisassembly()
		self.logger.info('BootLoader Extracting')
		informations.envVarList = os.environ
		informations.listPartitions = partition.partitionInformations(informations.currentMachine)
		informations.saveInformations()
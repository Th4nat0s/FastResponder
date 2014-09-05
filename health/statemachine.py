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

import os
import subprocess
import traceback

import psutil
from settings import NETWORK_ADAPTATER
from utils import write_to_output, get_csv_writer, write_to_csv, get_terminal_decoded_string, record_sha256_logs
import utils
import win32process
import wmi

class _Statemachine(object):
	def __init__(self,params):
		self.params=params
		self.wmi=wmi.WMI()
		self.computer_name=params['computer_name']
		self.output_dir=params['output_dir']+ '\\' +self.computer_name
		self.systemroot=params['system_root']
		self.logger=params['logger']
	
	def _list_network_drives(self):
		for disk in self.wmi.Win32_LogicalDisk (DriveType=4):
			yield disk.Caption,disk.FileSystem,disk.ProviderName
	
	def _list_drives(self):
		for physical_disk in self.wmi.Win32_DiskDrive ():
			for partition in physical_disk.associators ("Win32_DiskDriveToDiskPartition"):
				for logical_disk in partition.associators ("Win32_LogicalDiskToPartition"):   
					yield physical_disk.Caption, partition.Caption, logical_disk.Caption, logical_disk.FileSystem
	
	def _list_share(self):
		for share in self.wmi.Win32_Share ():
			yield share.Name, share.Path
	
	def _list_running(self):
		for process in self.wmi.Win32_Process():
			yield [process.ProcessId, process.Name,process.CommandLine, process.ExecutablePath]
	
	def _list_sessions(self):
		for session in self.wmi.Win32_Session():
			yield session.LogonId,session.AuthenticationPackage,session.StartTime,session.LogonType
	
	def _list_scheduled_jobs(self):
		path_task=self.system_root+'\\system32\\Tasks\\'
		for l in os.listdir(path_task):
			if os.path.isfile(path_task+l): 
				yield path_task+l
	
	def _list_network_adapters(self):
		net=self.wmi.Win32_NetworkAdapter()
		for n in net:
			netcard=n.Caption
			IPv4=''
			IPv6=''
			DHCP_server=''
			DNS_server=''
			adapter_type=''
			nbtstat_value=''
			if n.AdapterTypeID:
				adapter_type=NETWORK_ADAPTATER[int(n.AdapterTypeID)]
			net_enabled=n.NetEnabled
			mac_address=n.MACAddress
			description=n.Description
			physical_adapter=unicode(n.PhysicalAdapter)
			product_name=n.ProductName
			speed=n.Speed
			database_path=''
			if net_enabled:
				nic=self.wmi.Win32_NetworkAdapterConfiguration(MACAddress=mac_address)
				for nc in nic:
					database_path=nc.DatabasePath
					if nc.IPAddress:
						try:
							IPv4=nc.IPAddress[0]
							IPv6=nc.IPAddress[1]
						except IndexError as e:
								self.logger.error('Error to catch IP Address %s ' % str(nc.IPAddress))
					if IPv4:
						nbtstat='nbtstat -A '+ IPv4
						p=subprocess.Popen(nbtstat, shell=True, stdout=subprocess.PIPE)
						output, errors = p.communicate()
						#output=utils.decode_output_cmd(output)
						output = utils.get_terminal_decoded_string(output)
						nbtstat_value=output.split('\r\n')
						nbtstat_value=' '.join([n.replace('\n','') for n in nbtstat_value])
					if nc.DNSServerSearchOrder:
						DNS_server=nc.DNSServerSearchOrder[0]
					if nc.DHCPEnabled:
						if nc.DHCPServer:
							DHCP_server=nc.DHCPServer	
			yield netcard,adapter_type,description,mac_address,product_name,physical_adapter,product_name,speed,IPv4,IPv6,DHCP_server,DNS_server,database_path,nbtstat_value
		
	def _list_arp_table(self):
		cmd="arp -a"
		p=subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
		output, errors = p.communicate()
		output = utils.get_terminal_decoded_string(output)
		item = output.split("\n")
		for i in item:
			yield i
	
	def _list_route_table(self):
		route_table=self.wmi.Win32_IP4RouteTable()
		for r in route_table:
			yield r.Name,r.Mask
	
	def _list_sockets_network(self):
		for pid in win32process.EnumProcesses():
			try:			
				p=psutil.Process(pid)
				local_addr=''
				local_port=''
				remote_addr=''
				remote_port=''
				for connection in p.get_connections():
					if len(connection.local_address) >0:
						local_addr=connection.local_address[0]
						local_port=connection.local_address[1]
					if len(connection.remote_address)>0:
						remote_addr=connection.remote_address[0]
						remote_port=connection.remote_address[1]
					yield pid,p.name,local_addr,local_port,remote_addr,remote_port,connection.status
			except psutil._error.AccessDenied:
				pass
	
	def _list_services(self):
		services =self.wmi.Win32_Service()
		for s in services:
			yield s.Name,s.Caption,s.ProcessId,s.PathName,s.ServiceType,s.Status,s.State,s.StartMode
	
	def _csv_list_running_process(self,list_running):
		self.logger.info("Health : Listing running processes")
		with open(self.output_dir+'_processes.csv','ab') as fw:
			csv_writer = get_csv_writer(fw)
			#fw.write('"Computer Name"|"Type"|"PID"|"Name"|"Command"|"Path Exec"\r\n')
			for p in list_running:
				pid=p[0]
				name=p[1]
				cmd=p[2]
				exe_path=p[3]
				write_to_csv([self.computer_name, 'Running processes', unicode(pid), name, unicode(cmd), unicode(exe_path)], csv_writer)
		record_sha256_logs(self.output_dir +'_processes.csv',self.output_dir+'_sha256.log')
		
	def _csv_list_share(self,share):
		self.logger.info("Health : Listing shares")
		with open(self.output_dir + '_shares.csv','wb') as fw:
			csv_writer = get_csv_writer(fw)
			#fw.write('"Computer Name"|"Type"|"Name"|"Path"\r\n')
			for name,path in share:
				write_to_csv([self.computer_name, 'Shares', name, path], csv_writer)
		record_sha256_logs(self.output_dir +'_shares.csv',self.output_dir +'_sha256.log')
		
	def _csv_list_drives(self,drives):
		self.logger.info("Health : Listing drives")
		with open(self.output_dir+'_list_drives.csv','wb') as fw:
			csv_writer = get_csv_writer(fw)
			#fw.write('"Computer Name"|"Type"|"Fab"|"Partions"|"Disk"|"File System"\r\n')
			for phCapt,partCapt,logicalCapt,fs in drives:
				write_to_csv([self.computer_name, 'Drives', phCapt, partCapt, logicalCapt, fs], csv_writer)
		record_sha256_logs(self.output_dir + '_list_drives.csv',self.output_dir+'_sha256.log')
		
	def _csv_list_network_drives(self,drives):
		self.logger.info("Health : Listing network drives")
		with open(self.output_dir+'_list_networks_drives.csv','wb') as fw:
			csv_writer = get_csv_writer(fw)
			#fw.write('"Computer Name"|"Type"|"disque"|"fs"|"Partition Name"\r\n')
			for diskCapt,diskFs,diskPName in drives:
				write_to_csv([self.computer_name, 'Network drives', diskCapt, diskFs, diskPName], csv_writer)
		record_sha256_logs(self.output_dir+ '_list_networks_drives.csv',self.output_dir +'_sha256.log')
		
	def _csv_list_sessions(self,sessions):
		self.logger.info('Health : Listing sessions')
		with open(self.output_dir+'_sessions.csv','ab') as fw:
			csv_writer = get_csv_writer(fw)
			#fw.write('"Computer Name"|"Type"|"Logon ID"|"Authentication Package"|"Start Time"|"Logon Type"\r\n')
			for logonID,authenticationPackage,startime,logontype in sessions:
				write_to_csv([	self.computer_name, 'Active sessions', unicode(logonID),
								authenticationPackage, unicode(startime.split('.')[0]),  unicode(logontype)], csv_writer)
		record_sha256_logs(self.output_dir + '_sessions.csv',self.output_dir +'_sha256.log')
		
	def _csv_list_scheduled_jobs(self):
		self.logger.info('Health : Listing scheduled jobs')
		file_tasks=self.output_dir + '_tasks.csv'
		with open(file_tasks,'wb') as tasks_logs:
			proc=subprocess.Popen(["schtasks.exe",'/query','/fo','CSV'], stdout=subprocess.PIPE)
			res = proc.communicate()
			res = get_terminal_decoded_string(res[0])
			write_to_output(res, tasks_logs, self.logger)
		with open(file_tasks,"r") as fr, open(self.output_dir + "_scheduled_jobs.csv",'wb') as fw:
			csv_writer = get_csv_writer(fw)
			#fw.write('"Computer Name"|"Type"|"Name"|"Time"|"State"\r\n')
			for l in fr.readlines():
				l = l.decode('utf8')
				if l.find('\\') > 0:
					l = l[:-1].replace('"', '') # remove the end of line
					arr_write = [self.computer_name, 'Scheduled jobs'] + l.split(',')
					write_to_csv(arr_write, csv_writer)
		record_sha256_logs(self.output_dir +'_scheduled_jobs.csv',self.output_dir +'_sha256.log')
		
	def _csv_list_network_adapters(self,ncs):
		self.logger.info('Health : Listing network adapters')
		with open(self.output_dir + "_networks_cards.csv",'wb') as fw:
			csv_writer = get_csv_writer(fw)
			#fw.write('"Computer Name"|"Type"|"netcard"|"adapter_type"|"description"|"mac_address"|"product_name"|"physical_adapter"|"speed"|"IPv4"|"IPv6"|"DHCP_server"|"DNS_server"|"database_path"|"nbtstat_value"\r\n')
			for netcard,adapter_type,description,mac_address,product_name,physical_adapter,product_name,speed,IPv4,IPv6,DHCP_server,DNS_server,database_path,nbtstat_value in ncs:
				if netcard is None:
					netcard=' '
				if adapter_type is None:
					adapter_type=''
				if description is None:
					description=' '
				if mac_address is None:
					mac_address=' '
				if physical_adapter is None:
					physical_adapter=' '
				if product_name is None:
					product_name
				if speed is None:
					speed=' '
				if IPv4 is None:
					IPv4=' '
				if IPv6 is None:
					IPv6=''
				if DHCP_server is None:
					DHCP_server=' '
				if DNS_server is None:
					DNS_server=' '
				if database_path is None:
					database_path=' '
				if nbtstat_value is None:
					nbtstat_value=' '
				try:
					write_to_csv([self.computer_name,
					'Network adapter', netcard, adapter_type,
					description, mac_address, product_name,
					physical_adapter, speed, IPv4,
					IPv6, DHCP_server, DNS_server,
					database_path, nbtstat_value], csv_writer)
				except Exception:
					self.logger.error(traceback.format_exc())
		record_sha256_logs(self.output_dir +'_networks_cards.csv',self.output_dir +'_sha256.log') 						
			
	def _csv_list_arp_table(self,arp):
		self.logger.info('Health : Listing ARP tables')
		with open(self.output_dir + "_arp_table.csv",'wb') as fw:
			csv_writer = get_csv_writer(fw)
			#fw.write('"Computer Name"|"Type"|"IP"|"Mac"|"Status"\n')
			for entry in arp:
				entry.replace('\xff','')
				tokens=entry.split()
				entry_to_write=''
				if len(tokens)==3:
					entry_to_write='"'+self.computer_name+'"|"ARP table"|"'+'"|"'.join(tokens)+'"\n'
				if entry_to_write.find('\.')!=1 and len(entry_to_write) >0:
					arr_to_write = [self.computer_name, 'ARP table'] + tokens
					write_to_csv(arr_to_write, csv_writer)
		record_sha256_logs(self.output_dir +'_arp_table.csv',self.output_dir +'_sha256.log')
		
	def _csv_list_route_table(self,routes):
		self.logger.info('Health : Listing routes tables')
		with open(self.output_dir+"_routes_tables.csv",'ab') as fw:
			csv_writer = get_csv_writer(fw)
			#fw.write('"Computer Name"|"Route"|"Name"|"Mask"\r\n')
			for name,mask in routes:
				write_to_csv([self.computer_name, 'Route table', unicode(name), unicode(mask)], csv_writer)
		record_sha256_logs(self.output_dir +'_routes_tables.csv',self.output_dir +'_sha256.log')
		
	def _csv_list_sockets_network(self,connections):
		self.logger.info('Health : Listing sockets networks')
		with open(self.output_dir+'_sockets.csv','ab') as fw:
			csv_writer = get_csv_writer(fw)
			#fw.write('"Computer Name"|"Type"|"pid"|"name"|"local address"|"source port"|"remote addr"|"remote port"|"status"\r\n')
			for pid,name,local_address,source_port,remote_addr,remote_port,status in connections:
				write_to_csv([	self.computer_name, 'Sockets', unicode(pid),
								unicode(name), unicode(local_address), unicode(source_port),
								unicode(remote_addr), unicode(remote_port), unicode(status)], csv_writer)
		record_sha256_logs(self.output_dir +'_sockets.csv',self.output_dir +'_sha256.log')
		
	def _csv_list_services(self,services):
		self.logger.info('Health : Listing services')
		with open(self.output_dir+'_services.csv','ab') as fw:
			csv_writer = get_csv_writer(fw)
			#fw.write('"Computer Name"|"Type"|"name"|"caption"|"processId"|"pathName"|"serviceType"|"status"|"state"|"startMode"\r\n')
			for name,caption,processId,pathName,serviceType,status,state,startMode in services:
				write_to_csv([	self.computer_name, 'Services', caption,
								unicode(processId), serviceType, pathName,
								unicode(status), state, startMode], csv_writer)
		record_sha256_logs(self.output_dir +'_services.csv',self.output_dir +'_sha256.log')

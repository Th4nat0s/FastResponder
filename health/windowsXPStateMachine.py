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
from statemachine import _Statemachine
from settings import NETWORK_ADAPTATER
import utils
import subprocess
from utils import get_terminal_decoded_string, get_csv_writer, write_to_csv, write_to_output

class WindowsXPStateMachine(_Statemachine):
	def __init__(self,params):
		_Statemachine.__init__(self,params)
		
	def _list_share(self):
		return super(WindowsXPStateMachine,self)._list_share()
	
	def _list_running(self):
		return super(WindowsXPStateMachine,self)._list_running()
	
	def _list_drives(self):
		return super(WindowsXPStateMachine,self)._list_drives()
	
	def _list_network_drives(self):
		return super(WindowsXPStateMachine,self)._list_network_drives()
	
	def _list_sessions(self):
		return super(WindowsXPStateMachine,self)._list_sessions()
	
	def _list_scheduled_jobs(self):
		return super(WindowsXPStateMachine,self)._list_scheduled_jobs()
	
	def _list_network_adapters(self):
		self.logger.info('Health : Listing scheduled jobs')
		net=self.wmi.Win32_NetworkAdapter()
		for n in net:
			netcard=utils.decode_output_cmd(n.Caption)
			IPv4=''
			IPv6=''
			DHCP_server=''
			DNS_server=''
			adapter_type=''
			nbtstat_value=''
			if n.AdapterTypeID:
				adapter_type=NETWORK_ADAPTATER[int(n.AdapterTypeID)]
			netconnectionstatus=n.NetConnectionStatus
			mac_address=n.MACAddress
			description=n.Description
			physical_adapter=''
			product_name=''
			database_path=''
			speed=''
			if n.Speed:
				speed=n.Speed
			if netconnectionstatus:
				nic=self.wmi.Win32_NetworkAdapterConfiguration(MACAddress=mac_address)
				for nc in nic:
					if nc:
						if nc.DatabasePath:
							database_path=nc.DatabasePath
							database_path=database_path.replace('\n','')
						if nc.IPAddress:						
							IPv4=nc.IPAddress[0]
							if len(nc.IPaddress)>1: 
								IPv6=nc.IPAddress[1]
							nbtstat='nbtstat -A '+ IPv4
							p=subprocess.Popen(nbtstat, shell=True, stdout=subprocess.PIPE)
							output, errors = p.communicate()
							output=utils.decode_output_cmd(output)
							nbtstat_value=output.split('\r\n')
							nbtstat_value=''.join([n.replace('\n','') for n in nbtstat_value])
						if nc.DNSServerSearchOrder:
							DNS_server=nc.DNSServerSearchOrder[0]
							if nc.DHCPEnabled:
								DHCP_server=nc.DHCPServer	
			yield netcard,adapter_type,description,mac_address,product_name,physical_adapter,product_name,speed,IPv4,IPv6,DHCP_server,DNS_server,database_path,nbtstat_value
				
	def _list_arp_table(self):
		return super(WindowsXPStateMachine,self)._list_arp_table()
	
	def _list_route_table(self):
		return super(WindowsXPStateMachine,self)._list_route_table()
	
	def _list_sockets_network(self):
		return super(WindowsXPStateMachine,self)._list_sockets_network()
	
	def _list_sockets_services(self):
		return super(WindowsXPStateMachine,self)._list_services()
	
	def csv_list_drives(self):
		super(WindowsXPStateMachine,self)._csv_list_drives(self._list_drives())
		
	def csv_list_network_drives(self):
		super(WindowsXPStateMachine,self)._csv_list_network_drives(self._list_network_drives())
		
	def csv_list_share(self):
		super(WindowsXPStateMachine,self)._csv_list_share(self._list_share())
		
	def csv_list_running_proccess(self):
		super(WindowsXPStateMachine,self)._csv_list_running_process(self._list_running())
		
	def csv_list_sessions(self):
		super(WindowsXPStateMachine,self)._csv_list_sessions(self._list_sessions())
		
	def csv_list_scheduled_jobs(self):
		self.logger.info('Health : Listing scheduled jobs')
		file_tasks=self.output_dir + '_tasks.csv'
		with open(file_tasks, 'wb') as tasks_logs:
			proc=subprocess.Popen(["schtasks.exe",'/query','/fo','CSV'],stdout=subprocess.PIPE)
			res = proc.communicate()
			res = get_terminal_decoded_string(res[0])
			write_to_output(res, tasks_logs, self.logger)
		with open(file_tasks, "r") as fr, open(self.output_dir,'ab') as fw:
			csv_writer = get_csv_writer(fw)
			for l in fr.readlines():
				l = l.decode('utf8')[:-1].replace('"', '')
				if l.find(',') !=-1:
					write_to_csv([self.computer_name, 'Scheduled jobs'] + l.split(','), csv_writer)
		
	def csv_list_network_adapters(self):
		super(WindowsXPStateMachine,self)._csv_list_network_adapters(self._list_network_adapters())
		
	def csv_list_arp_table(self):
		super(WindowsXPStateMachine,self)._csv_list_arp_table(self._list_arp_table())
		
	def csv_list_route_table(self):
		super(WindowsXPStateMachine,self)._csv_list_route_table(self._list_route_table())
		
	def csv_list_sockets_networks(self):
		super(WindowsXPStateMachine,self)._csv_list_sockets_network(self._list_sockets_network())
		
	def csv_list_services(self):
		super(WindowsXPStateMachine,self)._csv_list_services(self._list_services())

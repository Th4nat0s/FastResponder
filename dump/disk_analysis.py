# -*- coding: utf-8 -*-
###############################################################################
#
#   FastResponder - Collect artefacts Windows for First Reponder
#    cert@sekoia.fr - http://www.sekoia.fr
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

import os
import time

import wmi


class DiskAnalysis(object):
    
    def __init__(self,path):
        self.currentMachine = wmi.WMI ()
        self.listDisks = []
        self.envVarList = {}
        self.listPartitions = []
        self.os = None
        self.mbrDisk = ""
        self.path=path+os.path.sep+'results.txt'
        

    
    def saveInformations(self):
    
        file = open(self.path, "w")
        
        file.write("\n\n-------------------------------" + time.strftime("%d/%m/%y %H:%M", time.localtime()) + "-----------------------------------------\n")
        
        file.write("\n-------------------------------MBR----------------------------------------------------\n")
        file.write(str(self.mbrDisk))
        file.write("\n\n-------------------------------Disks--------------------------------------------------\n\n")
        for i in range(len(self.listDisks)):
            file.write(self.listDisks[i].__str__())
        file.write("\n-------------------------------Partitions---------------------------------------------\n")
        file.write("\nSystem Partition : " +  self.envVarList["SYSTEMDRIVE"] + "\n" )
        for i in range(len(self.listPartitions)):
            file.write(self.listPartitions[i].__str__())
        file.write("\n\n-------------------------------Operating System---------------------------------------\n\n")
        #file.write(self.os.__str__())
        file.write("\n\n-------------------------------Environment Variables-----------------------------------\n\n")
        for key, value in self.envVarList.items():
            file.write("\nName : " + str(key) + "\nValue :" + str(value))
        file.close()
            
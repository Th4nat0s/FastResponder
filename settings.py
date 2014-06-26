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
from __future__ import unicode_literals
import os
import ctypes

OS='Windows'
CEV_ROOT = os.path.normpath(os.path.join(os.path.abspath(os.path.dirname(__file__)), "."))

EXTRACT_DUMP={
'mft': 'csv_mft',
'mbr':'csv_mbr'
}

NETWORK_ADAPTATER={
0:"Ethernet 802.3",
1:"Token Ring 802.5",
2:"Fiber Distributed Data Interface (FDDI)",
3:"Wide Area Network (WAN)",
4:"LocalTalk",
5:"Ethernet using DIX header format",
6:"ARCNET",
7:"ARCNET (878.2)",
8:"ATM",
9:"Wireless",
10:"Infrared Wireless",
11:"Bpc",
13:"CoWan",
14:"1394",
15:"Tunnel"
}

LONGLONGSIZE=ctypes.sizeof(ctypes.c_longlong)
BYTESIZE=ctypes.sizeof(ctypes.c_byte)
WORDSIZE=2
DWORDSIZE=4

USERS_FOLDER={
'Windows7':'C:\\Users',
'WindowsXP':'C\Documents and Settings'
}
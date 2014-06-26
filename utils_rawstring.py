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

import struct
import binascii
import wmi
import win32file



def hexbytes(xs, group_size=1, byte_separator=' ', group_separator=' '):
    #utility functions for printing data as hexdumps
    def ordc(c):
        return ord(c) if isinstance(c,str) else c
    
    if len(xs) <= group_size:
        s = byte_separator.join('%02X' % (ordc(x)) for x in xs)
    else:
        r = len(xs) % group_size
        s = group_separator.join(
            [byte_separator.join('%02X' % (ordc(x)) for x in group) for group in zip(*[iter(xs)]*group_size)]
        )
        if r > 0:
            s += group_separator + byte_separator.join(['%02X' % (ordc(x)) for x in xs[-r:]])
    return s.lower()

def hexprint(xs):
    def chrc(c):
        return c if isinstance(c,str) else chr(c)
    
    def ordc(c):
        return ord(c) if isinstance(c,str) else c
    
    def isprint(c):
        return ordc(c) in range(32,127) if isinstance(c,str) else c > 31
    
    return ''.join([chrc(x) if isprint(x) else '.' for x in xs])

def hexdump(xs, group_size=4, byte_separator=' ', group_separator='-', printable_separator='  ', address=0, address_format='%04X', line_size=16):
    if address is None:
        s = hexbytes(xs, group_size, byte_separator, group_separator)
        if printable_separator:
            s += printable_separator + hexprint(xs)
    else:
        r = len(xs) % line_size
        s = ''
        bytes_len = 0
        for offset in range(0, len(xs)-r, line_size):
            chunk = xs[offset:offset+line_size]
            bytes = hexbytes(chunk, group_size, byte_separator, group_separator)
            s += (address_format + ': %s%s\n') % (address + offset, bytes, printable_separator + hexprint(chunk) if printable_separator else '')
            bytes_len = len(bytes)
        
        if r > 0:
            offset = len(xs)-r
            chunk = xs[offset:offset+r]
            bytes = hexbytes(chunk, group_size, byte_separator, group_separator)
            bytes = bytes + ' '*(bytes_len - len(bytes))
            s += (address_format + ': %s%s\n') % (address + offset, bytes, printable_separator + hexprint(chunk) if printable_separator else '')
    
    return s

# decode ATRHeader from 
# analyzeMFT.py routines
# Copyright (c) 2010 David Kovar.
def decodeATRHeader(s):
    d = {}
    d['type'] = struct.unpack("<L",s[:4])[0]
    if d['type'] == 0xffffffff:
        return d
    d['len'] = struct.unpack("<L",s[4:8])[0]
    d['res'] = struct.unpack("B",s[8])[0]
    d['nlen'] = struct.unpack("B",s[9])[0]                    # This name is the name of the ADS, I think.
    d['name_off'] = struct.unpack("<H",s[10:12])[0]
    d['flags'] = struct.unpack("<H",s[12:14])[0]
    d['id'] = struct.unpack("<H",s[14:16])[0]
    if d['res'] == 0:
        d['ssize'] = struct.unpack("<L",s[16:20])[0]
        d['soff'] = struct.unpack("<H",s[20:22])[0]
        d['idxflag'] = struct.unpack("<H",s[22:24])[0]
    else:
        d['start_vcn'] = struct.unpack("<d",s[16:24])[0]
        d['last_vcn'] = struct.unpack("<d",s[24:32])[0]
        d['run_off'] = struct.unpack("<H",s[32:34])[0]
        d['compusize'] = struct.unpack("<H",s[34:36])[0]
        d['f1'] = struct.unpack("<I",s[36:40])[0]
        d['alen'] = struct.unpack("<d",s[40:48])[0]
        d['ssize'] = struct.unpack("<d",s[48:56])[0]
        d['initsize'] = struct.unpack("<d",s[56:64])[0]

    return d

def twos_comp(val, bits):
    """compute the 2's compliment of int value val"""
    if( (val&(1<<(bits-1))) != 0 ):
        val = val - (1<<bits)
    return val

#decode NTFS data runs from a MFT type 0x80 record ala: 
#http://inform.pucp.edu.pe/~inf232/Ntfs/ntfs_doc_v0.5/concepts/data_runs.html
def decodeDataRuns(dataruns):
    decodePos=0
    header=dataruns[decodePos]
    while header !='\x00':
        #print('HEADER\n' + hexdump(header))
        offset=int(binascii.hexlify(header)[0])
        runlength=int(binascii.hexlify(header)[1])
        #print('OFFSET %d LENGTH %d' %( offset,runlength))
        
        #move into the length data for the run
        decodePos+=1

        #print(decodePos,runlength)
        length=dataruns[decodePos:decodePos +int(runlength)][::-1]
        #print('LENGTH\n'+hexdump(length))
        length=int(binascii.hexlify(length),16)
            
        
        hexoffset=dataruns[decodePos +runlength:decodePos+offset+runlength][::-1]
        #print('HEXOFFSET\n' +hexdump(hexoffset))
        cluster=twos_comp(int(binascii.hexlify(hexoffset),16),offset*8)
        
        yield(length,cluster)
        decodePos=decodePos + offset+runlength
        header=dataruns[decodePos]
        #break

def get_physicalDrives():
    w=wmi.WMI ()
    for physical_disk in w.Win32_DiskDrive():
        yield physical_disk.DeviceID,get_physical_drive_size(physical_disk.DeviceID)

def get_physical_drive_size(drive='\\\\.\\PhysicalDrive0'):
    ''' Uses IOCTL to get physical drives size '''
    handle = win32file.CreateFile(drive, 0,win32file.FILE_SHARE_READ, None, win32file.OPEN_EXISTING, 0, 0)
    if handle:
        IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x00070000
        info = win32file.DeviceIoControl(handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, '', 24)
        win32file.CloseHandle(handle)
        if info:
            (cyl_lo, cyl_hi, media_type, tps, spt, bps) = struct.unpack('6L', info)
            mediasize = ((cyl_hi << 32) + cyl_lo) * tps * spt * bps
            """print mediasize, 'bytes'
            print mediasize/10**3, 'kbytes'
            print mediasize/10**6, 'Mbytes'
            print mediasize/10**9, 'Gbytes'"""
            return mediasize

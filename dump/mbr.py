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

from construct import *
from distorm3 import Decode, Decode16Bits
import hexdump
import os


class Mbr :

    def __init__(self,path):
    
        self.mbrHexa = ""
        self.mbrStruct = ""
        self.bootloaderCode = ""
        self.offset = 0
        self.partition = {"name" : []}
        self.signature = ""
        self.path=path
        self.mbr = Struct("mbr",
            HexDumpAdapter(Bytes("bootloaderCode", 446)),
            Array(4,
                Struct("partitions",
                    Enum(Byte("state"),
                        INACTIVE = 0x00,
                        ACTIVE = 0x80,
                    ),
                    BitStruct("beginning",
                        Octet("head"),
                        Bits("sect", 6),
                        Bits("cyl", 10),
                    ),
                    Enum(UBInt8("type"),
                        Nothing = 0x00,
                        FAT12_CHS = 0x01,
                        XENIX_ROOT = 0x02,
                        XENIX_USR = 0x03,
                        FAT16_16_32MB_CHS = 0x04,
                        Extended_DOS = 0x05,
                        FAT16_32MB_CHS = 0x06,
                        NTFS = 0x07,
                        FAT32_CHS = 0x0b,
                        FAT32_LBA = 0x0c,
                        FAT16_32MB_2GB_LBA = 0x0e,
                        Microsoft_Extended_LBA = 0x0f,
                        Hidden_FAT12_CHS = 0x11,
                        Hidden_FAT16_16_32MB_CHS = 0x14,
                        Hidden_FAT16_32MB_2GB_CHS = 0x16,
                        AST_SmartSleep_Partition = 0x18,
                        Hidden_FAT32_CHS = 0x1b,
                        Hidden_FAT32_LBA = 0x1c,
                        Hidden_FAT16_32MB_2GB_LBA = 0x1e,
                        PQservice = 0x27,
                        Plan_9_partition = 0x39,
                        PartitionMagic_recovery_partition = 0x3c,
                        Microsoft_MBR_Dynamic_Disk = 0x42,
                        GoBack_partition = 0x44,
                        Novell = 0x51,
                        CP_M = 0x52,
                        Unix_System_V = 0x63,
                        PC_ARMOUR_protected_partition = 0x64,
                        Solaris_x86_or_Linux_Swap = 0x82,
                        LINUX_NATIVE = 0x83,
                        Hibernation = 0x84,
                        Linux_Extended = 0x85,
                        NTFS_Volume_Set = 0x86,
                        BSD_OS = 0x9f,
                        FreeBSD = 0xa5,
                        OpenBSD = 0xa6,
                        Mac_OSX = 0xa8,
                        NetBSD = 0xa9,
                        Mac_OSX_Boot = 0xab,
                        MacOS_X_HFS = 0xaf,
                        BSDI = 0xb7,
                        BSDI_Swap = 0xb8,
                        Boot_Wizard_hidden = 0xbb,
                        Solaris_8_boot_partition = 0xbe,
                        CP_M_86 = 0xd8,
                        Dell_PowerEdge_Server_utilities_FAT_FS = 0xde,
                        DG_UX_virtual_disk_manager_partition = 0xdf,
                        BeOS_BFS = 0xeb,
                        EFI_GPT_Disk = 0xee,
                        EFI_System_Partition = 0xef,
                        VMWare_File_System = 0xfb,
                        VMWare_Swap = 0xfc,
                        _default_ = Pass,
                    ),
                    BitStruct("ending",
                        Octet("head"),
                        Bits("sect", 6),
                        Bits("cyl", 10),
                    ),
                    
                    ULInt32("sector_offset"), # offset from MBR in sectors
                    ULInt32("size"), # in sectors
                )
            ),
            Const(Bytes("signature", 2), "\x55\xAA"),
        )
        
    def saveMbr(self, image):        
        fileImage = open(image, "rb")
        fileMbr=open(self.path+os.path.sep+"mbr","wb")
        try :
            fileMbr.write(fileImage.read(512))
        except Exception as err :
            self.logger.error("Error to extract MBR")
        fileImage.close()
        fileMbr.close()
        return fileMbr.name
        
    
    def extractHexa(self,fileMbr):
        #file = open(fileMbr,"rb")
        hex = ""
        for line in fileMbr.split('\n'):
            hex = hex + line[10:58]
        hex=hex.replace(' ','')
        self.mbrHexa=hex

            
    def mbr_parsing(self, image):
        
        fileMbr = self.saveMbr(image)
        self.extractHexa(hexdump.hexdump(open(fileMbr,'rb').read(512),"return"))
        try :
            cap1 = self.mbrHexa.decode("hex")
            self.mbrStruct = self.mbr.parse(cap1)
            return self.mbrStruct
        except Exception as inst :
            self.logger.error("Error MBR Parsing")
             
    def bootLoaderDisassembly(self):
        l = Decode(0x000, self.mbrStruct.bootloaderCode, Decode16Bits)
        assemblyCode = ""
        for (offset,size, instruction, hexdump) in l:
            assemblyCode = assemblyCode + "%.8x: %-32s %s" % (offset, hexdump, instruction) +"\n"
        file = open(self.path+os.path.sep+"bootLoaderAssemblyCode.txt", "w")
        file.write(assemblyCode)

         

            
             
                

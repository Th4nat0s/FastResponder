#Fast Responder
##Concepts

This tool collects different artefacts on live Windows and records the results in csv files. With the analyses of this artefacts, an early compromission can be detected.
## Requirements
- pywin32
- python WMI
- python psutil
- python yaml
- construct
- distorm3
- hexdump
- pytz

## Execution
- ./fastresponder.py -h for help
- ./fastresponder.py --packages all  extract all artefacts without dump package artefacts
- ./fastresponder.py --packages dump --dump mft to extract MFT
- ./fastresponder.py --packages all --ouput_dir your_ouput_dir to set the directory output (by default is the current directory)
- ./fastresponder.py --profile you_file_profile to set your own profile extraction
## Packages

Packages Lists and Artefact

  * fs
    * IE History
    * Named Pipes
    * Prefetch
    * Recycle-bin
  * health
    * ARP Table
    * Drives list
    * Network drives
    * Networks Cards
    * Processes
    * Routes Tables
    * Tasks
    * Scheluded jobs
    * Services
    * Sessions
    * Network Shares
    * Sockets
  
  * registry
    * Installer Folders
    * OpenSaveMRU
    * Recents Docs
    * Services
    * Shellbags
    * Autoruns
    * USB History
    * Userassists
  * memory
    * Clipboard
    * dlls loaded
    * Opened Files
  * dump
    * MFT we use AnalyseMFT for https://github.com/dkovar/analyzeMFT
    * MBR
  

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

import ConfigParser
import argparse
import inspect
import logging
import multiprocessing
import os
import platform
import sys
import traceback
from datetime import datetime
from factory.factory import Factory
from settings import USERS_FOLDER, EXTRACT_DUMP, OS, CEV_ROOT
import settings




def set_logger(options):
	logger = logging.getLogger('FastResponder')
	logger.setLevel(logging.INFO)
	create_dir(options['output_dir'])
	fh = logging.FileHandler(os.path.join(options['output_dir'], 'FastResponder.log'), encoding='UTF-8')
	fl = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
	fh.setFormatter(fl)	
	logger.addHandler(fh)
	fs = logging.StreamHandler(sys.stdout)
	fs.setFormatter(fl)
	logger.addHandler(fs)
	options['logger'] = logger


def set_environment_options(options):
	operating_sys=platform.system()
	if operating_sys==settings.OS:
		release,version,csd,ptype = platform.win32_ver(release='', version='', csd='', ptype='')
	else:
		sys.stderr.write("OS not supported\n")
		sys.exit(1)

	options['system_root'] = os.environ["SYSTEMROOT"]	
	options['computer_name'] = os.environ["COMPUTERNAME"]
	options['USERPROFILE'] = USERS_FOLDER[operating_sys + release]
	options['OS'] = operating_sys
	options['release'] = release
	
	return options
		
def profile_used(path,options):
	file_conf=path
	config = ConfigParser.ConfigParser()
	config.readfp(open(file_conf))
	options['packages']=[ p.lower() for p in config.get('profiles', 'packages').split(',')]
	options['output_type']=config.get('output','type')
	options['output_destination']=config.get('output','destination')
	options['output_dir']=config.get('output','dir')
	options['dump']=config.get('dump','dump')
	return options

def create_dir(dir):
	''' Creates directory '''
	try:
		os.makedirs(dir)
	except OSError:
		pass

def create_output_dir(output_dir):
	''' Creates 'output_dir' recursively '''
	output_dir=output_dir+os.path.sep+datetime.now().strftime('%Y-%m-%d_%H%M%S')+os.path.sep
	create_dir(output_dir)

	return output_dir

def parse_command_line():
	''' Parse command line arguments and return them in a way that python can use directly '''

	parser = argparse.ArgumentParser(description='FastResponder')

	parser.add_argument('--packages',dest='packages',help='List of packages all,memory,registry,evt,fs,health. And advanced packages: filecatcher,dump \r\n use: --packages all or --packages fs,memory')
	parser.add_argument('--output_type',dest='output_type')
	parser.add_argument('--output_destination',dest='output_destination')
	parser.add_argument('--output_dir',dest='output_dir',help="directory of outputs csv of FastResponder")
	parser.add_argument('--share',dest='share')
	parser.add_argument('--dump',dest='dump', help='use: --dump ram if you want to dump ram. To list dump functionalities, --dump list')
	parser.add_argument('--profile',dest='profile', help='--profile yourfile.conf. The filepath must be absolute')

	args = parser.parse_args()
			
	if args.dump=="list":
		print ','.join(EXTRACT_DUMP.keys())
		sys.exit(0)

	return (args, parser)

def parse_config_file(config_file,options):
	''' Parse config file specified in argument, or default config file (CEV.conf) '''
	# If no config_file was specified, fallback to bundled config
	if config_file == None:
		config_file = 'CEV.conf'
	else:
		# If a config_file was specified but doesn't exist, tell the user and quit
		if not os.path.isfile(config_file):
			sys.stderr.write("Error: config file '%s' not found" % config_file)
			sys.exit(1)

	if os.path.isfile(config_file):
		return profile_used(config_file,options)
	else:
		return {}

def set_command_line_options(options, args):
	''' Override 'options' with command line options specified in 'args' '''
	for option in [ 'output_type', 'output_dir', 'dump']:
		if getattr(args, option):
			options[option] = getattr(args, option)
	
	for option in [ 'packages' ]:
		if getattr(args, option):
			options[option] = [ p.lower() for p in getattr(args, option).split(',')]
	return options

def validate_options(options, parser):
	''' Validate that 'options' are valid. If not, print usage and quit '''
	for option in [ 'output_dir', 'packages', 'output_type' ]:
		if option not in options:
			parser.print_help()
			sys.stderr.write("\nMissing required option: %s\n" % option)
			sys.exit(1)

	if 'dump' in options['packages']:
			if 'dump' not in options:
				parser.print_help()
				sys.stderr.write("\nMissing dump list\n")
				sys.exit(1)

	if 'fs' in options:
		if not 'size' in options and not 'mime_filter' in options:
			parser.print_help()
			sys.stderr.write("\nMissing fs filters ('size' and/or 'mime_filter')")
			sys.exit(1)

def set_options():
	''' Define all options needed for execution, based on config, command line and environment '''
	# First, parse command line arguments
	args, parser = parse_command_line()
	options={}

	# Parse the config file to load default options
	options = parse_config_file(args.profile,options)
	
	# Override with command line options, if any
	options = set_command_line_options(options, args)

	# Check if options are valid
	validate_options(options, parser)

	# Set options based on environment
	options = set_environment_options(options)

	return options

def main(options):
	f = Factory()

	set_logger(options)
	options['output_dir']=create_output_dir(options['output_dir'])

	modules = f.load_modules(options['packages'], options['output_dir'])
	
	for m in modules:
		classes = f.load_classes(m, options['OS'], options['release'])
		for cl in classes:
			instance = cl(options)
			if 'dump' in str(cl):
				for m in options['dump'].split(','):
					try:
						if options['output_type'] in EXTRACT_DUMP[m]:
							getattr(instance, EXTRACT_DUMP[m])()
					except Exception:
						options['logger'].error(traceback.format_exc())
				continue
			for name, method in inspect.getmembers(cl, predicate=inspect.ismethod):
				if not name.startswith('_'):
					try:
						if options['output_type'] in name:
							getattr(instance, name)()
					except Exception:
						options['logger'].error(traceback.format_exc())

if __name__ == "__main__":
	options = set_options()
	sys.exit(main(options))
		
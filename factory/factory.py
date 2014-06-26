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
from settings import CEV_ROOT
import os
import inspect
import importlib
import pkgutil

class Factory():
	def __filter_packages(self,modules,directories,output_dir):
		# Remove 'dump'
		for m in [ 'dump' ]:
			if m in directories and m not in modules:
				directories.remove(m)
		
		# Remove everything that is not a valid CE package
		copy = directories[:]
		for d in copy:
			if d.find('.') == 0 or str(self.__class__()).find(d) > 0 or d.startswith('_') or d == output_dir:
				directories.remove(d)

		# Remove everything not specified in module, unless module contains 'all'
		if not 'all' in modules:
			copy = directories[:]
			for d in copy:
				if not d in modules:
					directories.remove(d)

		# If dump is specified, put it in first position
		if 'dump' in directories:
			directories.remove('dump')
			directories.insert(0, 'dump')
			
		return directories

	def _list_packages(self):
		directories=[]
		lib_dir = CEV_ROOT
		if lib_dir.endswith('.zip'):
			lib_dir = lib_dir[0:-4]
		for root, dirnames, filenames in os.walk(lib_dir):
			directories=dirnames
			break

		return directories

	def _iter_modules(self, packages):
		for p in packages:
			if p != 'include':
				# TODO très moche... à remplacer plus tard
				imports = []
				try:
					for path_import in __import__(p).__path__:
						imports.append(path_import.replace('.zip', ''))
				except ImportError:
					pass
		
				for importer, modname, ispkg in pkgutil.iter_modules(imports):
					# quick fix for winXP
					if 'psutil' not in p:
						yield importlib.import_module(p+'.'+modname)

	def load_modules(self,filters,output_dir):
		directories = self._list_packages()
		self.__filter_packages(filters,directories,output_dir)
		
		return self._iter_modules(directories)
		
						
				
	def load_classes(self,module,os,release):
		for name,class_to_load in inspect.getmembers(module, inspect.isclass):
			if name.find(os+'All') != -1:
				yield class_to_load
			elif name.find(os+release) != -1:
				yield class_to_load

	def list_packages(self, filters, os, release):
		''' List available and activated packages '''
		result = {}
		packages = self._list_packages()

		copy = packages[:]
		for p in copy:
			if p.find('.') == 0:
				packages.remove(p)

		activated_packages = list(packages)
		activated_packages = self.__filter_packages(filters, activated_packages, '')

		for module in self._iter_modules(packages):
			classes = self.load_classes(module, os, release)
			for cl in classes:
				activated = False
				if module.__package__ in activated_packages:
					activated = True
				result[module.__package__] = activated
				break

		return result

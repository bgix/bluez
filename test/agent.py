#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import sys
import dbus
import dbus.service
import numpy

try:
  from termcolor import colored, cprint
  set_green = lambda x: colored(x, 'green', attrs=['bold'])
  set_cyan = lambda x: colored(x, 'cyan', attrs=['bold'])
except ImportError:
  set_green = lambda x: x
  set_cyan = lambda x: x

AGENT_IFACE = 'org.bluez.mesh.ProvisionAgent1'
AGENT_PATH = "/mesh/test/agent"

bus = None

def array_to_string(b_array):
	str_value = ""
	for b in b_array:
		str_value += "%02x" % b
	return str_value

class Agent(dbus.service.Object):
	def __init__(self, bus):
		self.path = AGENT_PATH
		self.bus = bus
		dbus.service.Object.__init__(self, bus, self.path)

	def get_properties(self):
		caps = []
		oob = []
		caps.append('out-numeric')
		caps.append('in-numeric')
		caps.append('public-oob')
		caps.append('static-oob')
		caps.append('static-256')
		oob.append('other')
		return {
			AGENT_IFACE: {
				'Capabilities': dbus.Array(caps, 's'),
				'OutOfBandInfo': dbus.Array(oob, 's')
			}
		}

	def get_path(self):
		return dbus.ObjectPath(self.path)

	@dbus.service.method(AGENT_IFACE, in_signature="", out_signature="")
	def Cancel(self):
		print("Cancel")

	@dbus.service.method(AGENT_IFACE, in_signature="su", out_signature="")
	def DisplayNumeric(self, type, value):
		print(set_cyan('DisplayNumeric ('), type,
				set_cyan(') number ='), set_green(value))

	@dbus.service.method(AGENT_IFACE, in_signature="", out_signature="ay")
	def PrivateKey(self):
		#private_key_str = '529aa0670d72cd6497502ed473502b037e8803b5c60829a5a3caa219505530ba'
		#public_key_str = 'f465e43ff23d3f1b9dc7dfc04da8758184dbc966204796eccf0d6cf5e16500cc0201d048bcbbd899eeefc424164e33c201c2b010ca6b4d43a8a155cad8ecb279'
		private_key_str = '6872b109ea0574adcf88bf6da64996a4624fe018191d9322a4958837341284bc'
		public_key_str = 'ce9027b5375fe5d3ed3ac89cef6a8370f699a2d3130db02b87e7a632f15b0002e5b72c775127dc0ce686002ecbe057e3d6a8000d4fbf2cdfffe0d38a1c55a043'
		print(set_cyan('PrivateKey ()'))
		print(set_cyan('Enter Public key on remote device: '),
						set_green(public_key_str));
		private_key = bytearray.fromhex(private_key_str)

		return dbus.Array(private_key, signature='y')

	@dbus.service.method(AGENT_IFACE, in_signature="s", out_signature="ay")
	def PromptStatic(self, type):
		if type == 'static-oob':
			static_key = numpy.random.randint(0, 255, 16)
			key_str = array_to_string(static_key)
		elif type == 'static-256':
			#static_key = numpy.random.randint(0, 255, 32)
			#key_str = array_to_string(static_key)
			key_str = '1234567812345678123456781234567812345678123456781234567812345678'
			static_key = bytearray.fromhex(key_str)

		print(set_cyan('PromptStatic ('), type, set_cyan(')'))
		print(set_cyan('Enter octet key on remote device: '),
							set_green(key_str));

		return dbus.Array(static_key, signature='y')

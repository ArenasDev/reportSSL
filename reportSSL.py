from sslyze import (
	ServerNetworkLocationViaDirectConnection,
	ServerConnectivityTester,
	Scanner,
	ServerScanRequest,
	ScanCommand,
)
from sslyze.errors import ConnectionToServerFailed
from sslyze.errors import ServerHostnameCouldNotBeResolved
import sys
import json
import os
from subprocess import Popen, PIPE
import signal
import time
import threading
from requests import Request, Session
import PIL
from PIL import ImageFont
from PIL import Image
from PIL import ImageDraw
from prettytable import PrettyTable
import binascii
import urllib3
urllib3.disable_warnings()


class ReportSSL:
	def __init__(self):
		self.output = ''
		self.imageFolder  = 'images'
		with open('ciphers.json') as j:
			self.ciphers = json.load(j)
		self.parseArgsAndCheckConnectivity()
		self.getAllCiphers()
		self.certificate()
		self.deprecatedTLS()
		self.TLSv1_3()
		self.downgradePrevention()
		self.OCSPStapling()
		self.specificAlg('RC4', None, 'Accepted RC4 cipher suites', 'RC4')
		self.specificAlg('3DES', None, 'Server is vulnerable to SWEET32 attacks because it supports block-based algorithms with block size of 64 (3DES)', 'SWEET32')
		self.specificAlg('CBC', ["SSLv2",  "SSLv3", "TLSv1.0"], 'Server is vulnerable to BEAST attacks.\nIt supports block-based algorithms (CBC) in SSLv2, SSLv3 or TLSv1.0', 'BEAST')
		self.specificAlg('CBC', ["SSLv3"], 'Server is vulnerable to POODLE attacks.\nIt supports block-based algorithms (CBC) in SSLv3', 'POODLE')
		self.drown()
		self.specificAlg('CBC', ["TLSv1.0", "TLSv1.1", "TLSv1.2"], 'Server is vulnerable to LUCKY13 attacks.\nIt supports block-based algorithms (CBC) in TLS', 'LUCKY13')
		self.logjamAndFreak()
		self.breach()
		self.crime()
		self.secureRenegotiation()
		self.robot()

		#TODO -> make openssl command a function to reduce code
		#TODO -> get security information from https://ciphersuite.info/cs/ of each cipher
		'''
		TIME ->
		HEIST ->
		SLOTH -> TLS 1.2, RSA-MD5 SIGNATURE -> generar un certificado de cliente con MD5 y enviarlo, si el servidor lo acepta es vulnerable
		HEARTBLEED
		ZOMBIE
		GOLDENDOODLE
		client renegotiation
		'''

	def parseArgsAndCheckConnectivity(self):
		if len(sys.argv) == 3 or len(sys.argv) == 4:
			if len(sys.argv) == 4:
				if sys.argv[1] == '--verbose':
					self.verbose = True
					self.host = sys.argv[2]
					self.port = sys.argv[3]
				else:
					self.printHelp()
			else:
				self.verbose = False
				self.host = sys.argv[1]
				self.port = sys.argv[2]
			try:
				print('Testing connectivity ...', end='', flush=True)
				# Define the server that you want to scan
				serverLocation = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(self.host, self.port)

				# Do connectivity testing to ensure SSLyze is able to connect
				self.serverInfo = ServerConnectivityTester().perform(serverLocation)
			except ConnectionToServerFailed as e:
				# Could not connect to the server; abort
				print(f"Error connecting to {serverLocation}: {e.error_message}")
				sys.exit()
			except ServerHostnameCouldNotBeResolved:
				print(f"Cannot resolve {self.host}, check that it is correct (IP is correct and domain does not include protocol)")
				sys.exit()
			print(" COMPLETED.")
			self.highestProtocol = self.serverInfo.tls_probing_result.highest_tls_version_supported.name
		else:
			self.printHelp()

	def printHelp(self):
		print('Execute:\n\tpython reportSSL.py www.google.es 443\t\t(for silent mode)\n\tpython reportSSL.py --silent www.google.es 443\t\t(for verbose mode)')
		sys.exit()		

	def getAllCiphers(self):
		self.allCiphers = {}
		print('Retrieving ciphers for each protocol and checking order ...', end='', flush=True)
		results = self.initiateScan({ScanCommand.SSL_2_0_CIPHER_SUITES, ScanCommand.SSL_3_0_CIPHER_SUITES, ScanCommand.TLS_1_0_CIPHER_SUITES, ScanCommand.TLS_1_1_CIPHER_SUITES, ScanCommand.TLS_1_2_CIPHER_SUITES, ScanCommand.TLS_1_3_CIPHER_SUITES})
		keys = {"SSLv2" : ScanCommand.SSL_2_0_CIPHER_SUITES, "SSLv3" : ScanCommand.SSL_3_0_CIPHER_SUITES, "TLSv1.0" : ScanCommand.TLS_1_0_CIPHER_SUITES, "TLSv1.1" : ScanCommand.TLS_1_1_CIPHER_SUITES, "TLSv1.2" : ScanCommand.TLS_1_2_CIPHER_SUITES, "TLSv1.3" : ScanCommand.TLS_1_3_CIPHER_SUITES}
		order = []

		for result in results:
			for key in keys.keys():
				self.allCiphers.update({key : []})
				try:
					tls = result.scan_commands_results[keys[key]]
					for cipher in tls.accepted_cipher_suites:
						try:
							elem = self.ciphers[cipher.cipher_suite.name]
							# print(cipher.cipher_suite)
							self.allCiphers[key].append(cipher)
						except Exception:
							print(f'Cipher {cipher.cipher_suite.name} not found in database')
				except KeyError:
					print(key + ' scan failed')

				#Check if server has cipher order preference
				if tls.cipher_suite_preferred_by_server == None:
					order.append(key)

		if len(order) > 0:
			print(' No cipher order for certain protocols.')
			self.generateImageAndPrintInfo(f"Server does not have cipher order for the following supported protocols (server {self.host}):", ', '.join(order), 'CIPHER_ORDER', None, None)
		else:
			print()

	#check
	def certificate(self):
		print('Checking certificate ...', end='', flush=True)
		results = self.initiateScan({ScanCommand.CERTIFICATE_INFO})
		check = False

		for result in results:
			for cert in result.scan_commands_results[ScanCommand.CERTIFICATE_INFO].certificate_deployments:
				#Check if hostname matches certificate name
				if not cert.leaf_certificate_subject_matches_hostname:
					check = True
					data = 'Hostname: ' + result.scan_commands_results[ScanCommand.CERTIFICATE_INFO].hostname_used_for_server_name_indication + '\n'
					data += 'Certificate name: ' + str(result.scan_commands_results[ScanCommand.CERTIFICATE_INFO].certificate_deployments[0].received_certificate_chain[0].subject).replace('<Name(', '').replace(')>', '').split('CN=')[1].split(',')[0] + '\n'
					print(' HOSTNAME MISMATCH', end='', flush=True)
					self.generateImageAndPrintInfo('Certificate is not trusted because it does not match hostname', data, 'CertificateUntrustedNameMismatch', None, None)
		print()
				
	def deprecatedTLS(self):
		keys = ["TLSv1.0", "TLSv1.1"]

		print('Checking usage of deprecated TLS ...', end='', flush=True)
		for key in keys:
			pt = PrettyTable(border=False)
			pt.field_names = ["Hexcode", "Cipher Suite Name (OpenSSL)", "Key Exch.", "Encryption", "Bits", "Cipher Suite Name (IANA/RFC)"]
			pt.align = 'l'
			ciphers = self.allCiphers[key]
			
			for cipher in ciphers:
				try:
					elem = self.ciphers[cipher.cipher_suite.name]
					pt.add_row([elem[1], elem[0], elem[2], elem[3], elem[4], cipher.cipher_suite.name])
				except Exception:
					print(f'Cipher {cipher.cipher_suite.name} not found in database')
		if len(ciphers) > 0:
			print(' VULNERABLE.')
			self.generateImageAndPrintInfo(f"Accepted cipher suites for {key} (server {self.host}):", pt, key, 0, 1 + len(str(pt).split('\n')))
		else:
			print()

	def specificAlg(self, alg, protos, header, fileName):
		if protos != None:
			pr = ', '.join(protos)
			print(f'Checking {alg} in {pr} ...', end='', flush=True)
		else:
			print(f'Checking {alg} ...', end='', flush=True)
		pt = PrettyTable(border=False)
		pt.field_names = ["Hexcode", "Cipher Suite Name (OpenSSL)", "Key Exch.", "Encryption", "Bits", "Cipher Suite Name (IANA/RFC)"]
		pt.align = 'l'
		check = False
		#if no protocol is specified, check all
		if protos == None:
			protos = self.allCiphers.keys()
		for key in protos:
			pt.add_row([key, '', '', '', '', ''])
			for cipher in self.allCiphers[key]:
				elem = self.ciphers[cipher.cipher_suite.name]
				if alg in cipher.cipher_suite.name:
					check = True
					pt.add_row([elem[1], elem[0], elem[2], elem[3], elem[4], cipher.cipher_suite.name])

		if check:
			print(' VULNERABLE.')
			self.generateImageAndPrintInfo(f"{header} (server {self.host}):", pt, fileName, None, None)
		else:
			print()

	def drown(self):
		print('Checking DROWN ...', end='', flush=True)
		if len(self.allCiphers["SSLv2"]) > 0:
			print('ciphers in SSLv2')
			pt = PrettyTable(border=False)
			pt.field_names = ["Hexcode", "Cipher Suite Name (OpenSSL)", "Key Exch.", "Encryption", "Bits", "Cipher Suite Name (IANA/RFC)"]
			pt.align = 'l'
			for cipher in self.allCiphers["SSLv2"]:
				elem = self.ciphers[cipher.cipher_suite.name]
				pt.add_row([elem[1], elem[0], elem[2], elem[3], elem[4], cipher.cipher_suite.name])

			print(' VULNERABLE.')
			self.generateImageAndPrintInfo(f"Server is vulnerable to DROWN attacks because it supports SSLv2 (server {self.host}):", pt, 'DROWN', None, None)
		else:
			print()

	def logjamAndFreak(self):
		print('Checking LOGJAM and FREAK ...', end='', flush=True)
		ptL = PrettyTable(border=False)
		ptL.field_names = ["Hexcode", "Cipher Suite Name (OpenSSL)", "Key Exch.", "Encryption", "Bits", "Cipher Suite Name (IANA/RFC)", "Key Size", "Key Ex. Type"]
		ptL.align = 'l'
		ptF = PrettyTable(border=False)
		ptF.field_names = ["Hexcode", "Cipher Suite Name (OpenSSL)", "Key Exch.", "Encryption", "Bits", "Cipher Suite Name (IANA/RFC)", "Key Size", "Key Ex. Type"]
		ptF.align = 'l'
		logjam = False
		freak = False
		for key in ["TLSv1.0", "TLSv1.1", "TLSv1.2"]:
			ptL.add_row([key, '', '', '', '', '', '', ''])
			ptF.add_row([key, '', '', '', '', '', '', ''])
			for cipher in self.allCiphers[key]:
				elem = self.ciphers[cipher.cipher_suite.name]
				if '_DHE_' in cipher.cipher_suite.name:
					if cipher.ephemeral_key.size <= 1024:
						logjam = True
						ptL.add_row([elem[1], elem[0], elem[2], elem[3], elem[4], cipher.cipher_suite.name, cipher.ephemeral_key.size, cipher.ephemeral_key.type])
					if cipher.ephemeral_key.size <= 512:
						freak = True
						ptF.add_row([elem[1], elem[0], elem[2], elem[3], elem[4], cipher.cipher_suite.name, cipher.ephemeral_key.size, cipher.ephemeral_key.type])

		if freak:
			print(' VULNERABLE FOR BOTH.')
			self.generateImageAndPrintInfo(f"Server is vulnerable to FREAK attacks.\nIt supports Ephemeral Diffie-Hellman algorithms (EDH) with key sizes of 512 or lower (server {self.host}):", ptF, 'LOGJAM', None, None)
		elif logjam:
			print(' VULNERABLE FOR LOGJAM.')
			self.generateImageAndPrintInfo(f"Server is vulnerable to LOGJAM attacks.\nIt supports Ephemeral Diffie-Hellman algorithms (EDH) with key sizes of 1024 or lower (server {self.host}):", ptL, 'LOGJAM', None, None)
		else:
			print()

	def breach(self):
		print('Checking BREACH ...', end='', flush=True)
		s = Session()
		headers = {"Host" : self.host, "Accept-Encoding" : "compress, gzip"}
		req = Request('GET', "https://" + self.host+ ':' + self.port,  headers = headers)
		prepped = req.prepare()
		# , proxies = {"https" : "127.0.0.1:8080"}
		res = s.send(prepped, verify=False, allow_redirects=True, stream=True)
		# print(res.raw.read(100))

		if 'Content-Encoding' in res.headers.keys():
			#May exist other values, havent found them yet
			if 'gzip' in res.headers['Content-Encoding']:
				request = '{}\n{}\r\n{}\r\n\r\n'.format(
						'-----------REQUEST-----------',
						prepped.method + ' ' + prepped.url,
						'\r\n'.join('{}: {}'.format(k, v) for k, v in prepped.headers.items())
					)
				response = '-----------RESPONSE-----------'
				for k, v in res.headers.items():
					aux = '{}: {}'.format(k, v)
					mod = len(aux) % 80
					i = int(len(aux) / 80)
					if i > 0:
						for counter in range(i):
							response += '\r\n' + aux[80 * counter:80 * counter + 80]
						if mod > 0:
							response += '\r\n' + aux[80 * counter + 80:]
					else:
						response += '\r\n' + '{}: {}'.format(k, v)

				resp = res.raw.read(80 * 4)
				response += '\r\n'
				for counter in range(4):
					response += '\r\n' + resp[80 * counter:80 * counter + 80].decode('latin-1')
				res.close()

				data = request + response
				index = None
				for line in data.split('\n'):
					if 'Content-Encoding' in line:
						print(' VULNERABLE.')
						self.generateImageAndPrintInfo(f"Server is vulnerable to BREACH attacks.\nIt supports gzip compression in the HTTP responses (server {self.host}):", data, 'BREACH', data.split('\n').index(line) + 1, data.split('\n').index(line) + 1)
						break
			else:
				print()

	def crime(self):
		print('Checking CRIME ...', end='', flush=True)
		self.finishOpenSSL = threading.Event()
		self.output = ''
		p = Popen(os.getcwd() + '\\OpenSSL\\bin\\openssl.exe s_client -connect ' + self.host + ':' + self.port, stdin=PIPE, stdout=PIPE, stderr=PIPE)
		t = threading.Thread(target=self.outputReader, args=(p, 'Compression:'))
		t.start()

		while not self.finishOpenSSL.is_set():
			time.sleep(1)
		p.terminate()

		#Handle output to make image
		data = 'Command: openssl.exe s_client -connect ' + self.host + ':' + self.port + '\n\n'
		data += self.output.split('-----BEGIN CERTIFICATE-----')[0]
		data += '[redacted]'
		data += self.output.split('-----END CERTIFICATE-----')[1]

		for line in range(len(data)):
			if 'Compression:' in data[line] and 'NONE' not in data[line]:
				print(' VULNERABLE.')
				self.generateImageAndPrintInfo(f"Server is vulnerable to CRIME attacks.\nIt supports TLS-level compression (server {self.host}):", data, 'CRIME', line, line)
				return
		print()

	def secureRenegotiation(self):
		print('Checking SECURE RENEGOTIATION ...', end='', flush=True)
		self.finishOpenSSL = threading.Event()
		self.output = ''
		p = Popen(os.getcwd() + '\\OpenSSL\\bin\\openssl.exe s_client -connect ' + self.host + ':' + self.port, stdin=PIPE, stdout=PIPE, stderr=PIPE)
		t = threading.Thread(target=self.outputReader, args=(p, 'Secure Renegotiation'))
		t.start()

		while not self.finishOpenSSL.is_set():
			time.sleep(1)
		p.terminate()

		#Handle output to make image
		data = 'Command: openssl.exe s_client -connect ' + self.host + ':' + self.port + '\n\n'
		data += self.output.split('-----BEGIN CERTIFICATE-----')[0]
		data += '[redacted]'
		data += self.output.split('-----END CERTIFICATE-----')[1]

		for line in range(len(data)):
			if 'Secure Renegotiation' in data[line] and 'IS NOT' in data[line]:
				print(' NOT SUPPORTED.')
				self.generateImageAndPrintInfo(f"Server does not support Secure Renegotiation (server {self.host}):", data, 'SECURE_RENEG', line, line)
				return
		print()

	def robot(self):
		#From testssl: A list of all non-PSK cipher suites that use RSA key transport
		nonPSK = ["0x9d", "0xc0a1", "0xc09d", "0x3d", "0x35", "0xc0", "0x84", "0xc03d", "0xc051", "0xc07b", "0xff00", "0xff01", "0xff02", "0xff03", "0xc0a0", "0xc09c", "0x9c", "0x3c", "0x2f", "0xba", "0x96", "0x41", "0x07", "0xc03c", "0xc050", "0xc07a", "0x05", "0x04", "0x0a", "0xfeff", "0xffe0", "0x62", "0x09", "0x61", "0xfefe", "0xffe1", "0x64", "0x60", "0x08", "0x06", "0x03", "0x3b", "0x02", "0x01"]
		check = False

		print('Checking ROBOT (this can take a while)...', end='', flush=True)
		results = self.initiateScan({ScanCommand.ROBOT})

		for result in results:
			enumResult = result.scan_commands_results[ScanCommand.ROBOT].robot_result.value
			if enumResult <= 2:
				pt = PrettyTable(border=False)
				pt.field_names = ["Hexcode", "Cipher Suite Name (OpenSSL)", "Key Exch.", "Encryption", "Bits", "Cipher Suite Name (IANA/RFC)"]
				pt.align = 'l'
				for key in self.allCiphers.keys():
					ciphers = self.allCiphers[key]
					
					for cipher in ciphers:
						try:
							elem = self.ciphers[cipher.cipher_suite.name]
							if elem[1] in nonPSK:
								check = True
								print(elem)
								pt.add_row([elem[1], elem[0], elem[2], elem[3], elem[4], cipher.cipher_suite.name])
						except Exception:
								print(f'Cipher {cipher.cipher_suite.name} not found in database')
				if check:
					if enumResult == 1:
						print(' POTENTIALLY VULNERABLE.')
						self.generateImageAndPrintInfo(f"Server is POTENTIALLY vulnerable to ROBOT attacks\nIt supports non-PSK cipher suites that use RSA key transport (server {self.host}):", pt, 'ROBOT', None, None)
					else:
						print(' VULNERABLE.')
						self.generateImageAndPrintInfo(f"Server is vulnerable to ROBOT attacks\nIt supports non-PSK cipher suites that use RSA key transport (server {self.host}):", pt, 'ROBOT', None, None)
				else:
					print()

	def TLSv1_3(self):
		print('Checking support of TLSv1.3 ...', end='', flush=True)
		if len(self.allCiphers["TLSv1.3"]) == 0:
			print(' NOT SUPPORTED.')
			self.generateImageAndPrintInfo('Server does not support TLSv1.3', 'The server does not support TLSv1.3 which is the only version of TLS\nthat currently has no known flaws or exploitable weaknesses.\n\nHighest supported protocol is ' + self.highestProtocol.replace('TLS_', 'TLSv').replace('SSL_', 'SSLv').replace('_', '.'), 'TLSv1.3NotSupported', None, None)
		else:
			print()

	def downgradePrevention(self):
		print('Checking DOWNGRADE PREVENTION ...', end='', flush=True)
		results = self.initiateScan({ScanCommand.TLS_FALLBACK_SCSV})

		for result in results:
			if not result.scan_commands_results[ScanCommand.TLS_FALLBACK_SCSV].supports_fallback_scsv:
				protocolFlag = '-no_'
				#Check highest protocol to prevent its use in openssl
				if 'tls' in self.highestProtocol.lower() or 'ssl' in self.highestProtocol.lower():
					protocolFlag += self.highestProtocol.lower().replace('tls_', 'tls').replace('ssl_', 'ssl').replace('_0', '')
				else:
					print('Potentially vulnerable to downgrade attack. Highest supported protocol is not TLS or SSL.')
					return


				self.finishOpenSSL = threading.Event()
				self.output = ''
				p = Popen(os.getcwd() + '\\OpenSSL\\bin\\openssl.exe s_client -connect ' + self.host + ':' + self.port + ' -fallback_scsv ' + protocolFlag, stdin=PIPE, stdout=PIPE, stderr=PIPE)
				t = threading.Thread(target=self.outputReader, args=(p, 'Master-Key'))
				t.start()

				while not self.finishOpenSSL.is_set():
					time.sleep(1)
				p.terminate()

				#Handle output to make image
				data = 'Command: openssl.exe s_client -connect ' + self.host + ':' + self.port + ' -fallback_scsv ' + protocolFlag + '\n\n'
				data += self.output.split('-----BEGIN CERTIFICATE-----')[0]
				data += '[redacted]'
				data += self.output.split('-----END CERTIFICATE-----')[1]

				for line in range(len(data)):
					if 'New,' in data[line] and ', Cipher is ' in data[line]:
						print(' NOT SUPPORTED.')
						self.generateImageAndPrintInfo(f"Downgrade prevention is not provided (server {self.host}):", data, 'downgradePrevention', line, line)
						break
			else:
				print()

	def OCSPStapling(self):
		print('Checking OCSP Stapling support ...', end='', flush=True)
		self.finishOpenSSL = threading.Event()
		self.output = ''
		p = Popen(os.getcwd() + '\\OpenSSL\\bin\\openssl.exe s_client -connect ' + self.host + ':' + self.port + ' -status', stdin=PIPE, stdout=PIPE, stderr=PIPE)
		t = threading.Thread(target=self.outputReader, args=(p, '-----BEGIN CERTIFICATE-----'))
		t.start()

		while not self.finishOpenSSL.is_set():
			time.sleep(1)
		p.terminate()

		for line in self.output.split('\n'):
			if 'OCSP response: no response sent' in line:
				print(' NOT SUPPORTED.')
				self.generateImageAndPrintInfo(f"OCSP Stapling not supported (server {self.host}):", '\n'.join(self.output.split('\n')[:self.output.split('\n').index('-----BEGIN CERTIFICATE-----')]), 'OCSPStaplingNotSupported', self.output.split('\n').index(line), self.output.split('\n').index(line))
				return
		print()

	def outputReader(self, proc, finish):
		for line in iter(proc.stdout.readline, b''):
			if finish in line.decode('utf-8'):
				self.finishOpenSSL.set()
			self.output += '{0}'.format(line.decode('utf-8'))

	def initiateScan(self, commands):
		self.scanner = Scanner()
		serverScanReq = ServerScanRequest(
			server_info = self.serverInfo, scan_commands = commands,
		)
		self.scanner.queue_scan(serverScanReq)

		return self.scanner.get_results()

	def generateImageAndPrintInfo(self, prev, pt, imageName, startLine, endLine):
		data = ''
		self.printt('')
		self.printt(prev)
		data += prev + '\n'
		if len(prev.split('\n')) > 1:
			self.printt('-' * len(prev.split('\n')[-1]))
			data += '-' * len(prev.split('\n')[-1]) + '\n'
		else:
			self.printt('-' * len(prev))
			data += '-' * len(prev) + '\n'

		#Delete first whitespace result of deleting borders
		if isinstance(pt, PrettyTable):
			table = str(pt).split('\n')[0][1:] + '\n'
			table += '-' * len(str(pt).split('\n')[0]) + '\n'
			for line in str(pt).split('\n')[1:]:
				table += line[1:] + '\n'
			self.printt(table)
			data += table
		else:
			self.printt(pt)
			data += pt
		self.text2png(data, self.imageFolder + '/' + imageName + '(' + self.host + '_' + self.port + ').png', startLine = startLine, endLine = endLine)

	def printt(self, text):
		if self.verbose:
			print(text)


	def text2png(self, text, fullpath, color = "#000", bgcolor = "#FFF", fontsize = 30, padding = 10, startLine = None, endLine = None):
		font = ImageFont.truetype("consola.ttf", fontsize)

		width = font.getsize(max(text.split('\n'), key = len))[0] + (padding * 2)
		lineHeight = font.getsize(text)[1]
		imgHeight = lineHeight * (len(text.split('\n')) + 1) + padding
		img = Image.new("RGBA", (width, imgHeight), bgcolor)
		draw = ImageDraw.Draw(img)

		y = padding
		#Draw the text
		for line in text.split('\n'):
			draw.text((padding, y), line, color, font=font)
			y += lineHeight

		#Draw the highlight rectangle, have to use line instead of rectangle because it does not support line THICCness
		if startLine != None and endLine != None and endLine >= startLine:
			#Add 2 to each bound because of the two heading lines
			if startLine == endLine:
				endLine += 1
			startLine += 2
			endLine += 2
			point1 = (3, (padding / 2) + 3 + lineHeight * startLine)
			point2 = (3 + font.getsize(text.split('\n')[startLine])[0] + padding, (padding / 2) + 3 + lineHeight * startLine)
			point3 = (3 + font.getsize(text.split('\n')[startLine])[0] + padding, padding + 3 + lineHeight * (startLine + (endLine - startLine)))
			point4 = (3, padding + 3 + lineHeight * (startLine + (endLine - startLine)))
			draw.line((point1, point2, point3, point4, point1), fill="red", width=5)

		if not os.path.exists(self.imageFolder):
			os.makedirs(self.imageFolder)

		img.save(fullpath, quality=100)

if __name__ == '__main__':
	ReportSSL()

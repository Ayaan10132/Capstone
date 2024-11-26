import os
import yara
import json

class  yaraScan():

	def __init__(self,filename):
		self.filename=filename
		

		
		
	def results(self):
		results={}
		results={
		'Malware': '%s' % self.is_malware(),
		'AntiVm' : '%s' %self.is_antidb_antivm() ,
		'Crypto Used': '%s' % self.check_crypto(),
		'File Packed': '%s' %self.is_file_packed(),
		}
		return results

			
	def is_file_packed(self):
			"""These Yara rules detect common packers and compilers."""
			# Define directories
			rules_dir = "./App/yarascripts/YaraScan/rules/packers"
			compiled_dir = "./App/yarascripts/YaraScan/rules_compiled/packers"

			try:
					# Create both directories if they don't exist
					os.makedirs(rules_dir, exist_ok=True)
					os.makedirs(compiled_dir, exist_ok=True)
					
					# Only proceed if the rules directory has files
					if os.path.exists(rules_dir) and os.listdir(rules_dir):
							for n in os.listdir(rules_dir):
									rule_path = os.path.join(rules_dir, n)
									if not os.path.isdir(rule_path):
											try:
													compiled_path = os.path.join(compiled_dir, n)
													rule = yara.compile(rule_path)
													rule.save(compiled_path)
													rule = yara.load(compiled_path)
													m = rule.match(self.filename)
													if m:
															return m
											except Exception as e:
													print(f"Error processing packer rule {n}: {str(e)}")
													continue
					return None
									
			except Exception as e:
					print(f"Error setting up packer directories: {str(e)}")
					return None


	def is_malicious_document(self):
		if not os.path.exists("./App/yarascripts/YaraScan/rules_compiled/maldocs"):
			os.mkdir("./App/yarascripts/YaraScan/rules_compiled/maldocs")
		for n in os.listdir("./App/yarascripts/YaraScan/rules/maldocs"):
			rule = yara.compile("./App/yarascripts/YaraScan/rules/maldocs/" + n)
			rule.save("./App/yarascripts/YaraScan/rules_compiled/maldocs/" + n)
			rule = yara.load("./App/yarascripts/YaraScan/rules_compiled/maldocs/" + n)
			m = rule.match(self.filename)
			if m:
				return m


	def is_antidb_antivm(self):
		"""These Yara rules try to detect anti-debug and anti-vm techniques."""
		# Define directories
		rules_dir = "./App/yarascripts/YaraScan/rules/antidebug_antivm"
		compiled_dir = "./App/yarascripts/YaraScan/rules_compiled/antidebug_antivm"

		try:
			# Create both directories if they don't exist
			os.makedirs(rules_dir, exist_ok=True)
			os.makedirs(compiled_dir, exist_ok=True)
			
			# Only proceed if the rules directory has files
			if os.path.exists(rules_dir) and os.listdir(rules_dir):
				for n in os.listdir(rules_dir):
					rule_path = os.path.join(rules_dir, n)
					if not os.path.isdir(rule_path):
						try:
							compiled_path = os.path.join(compiled_dir, n)
							rule = yara.compile(rule_path)
							rule.save(compiled_path)
							rule = yara.load(compiled_path)
							m = rule.match(self.filename)
							if m:
								return m
						except Exception as e:
							print(f"Error processing antidebug/antivm rule {n}: {str(e)}")
							continue
			return None
							
		except Exception as e:
			print(f"Error setting up antidebug/antivm directories: {str(e)}")
			return None


	def check_crypto(self):
		"""These Yara rules detect cryptographic algorithms."""
		# Define directories
		rules_dir = "./App/yarascripts/YaraScan/rules/crypto"
		compiled_dir = "./App/yarascripts/YaraScan/rules_compiled/crypto"

		try:
			# Create both directories if they don't exist
			os.makedirs(rules_dir, exist_ok=True)
			os.makedirs(compiled_dir, exist_ok=True)
			
			# Only proceed if the rules directory has files
			if os.path.exists(rules_dir) and os.listdir(rules_dir):
				for n in os.listdir(rules_dir):
					rule_path = os.path.join(rules_dir, n)
					if not os.path.isdir(rule_path):
						try:
							compiled_path = os.path.join(compiled_dir, n)
							rule = yara.compile(rule_path)
							rule.save(compiled_path)
							rule = yara.load(compiled_path)
							m = rule.match(self.filename)
							if m:
								return m
						except Exception as e:
							print(f"Error processing crypto rule {n}: {str(e)}")
							continue
			return None
							
		except Exception as e:
			print(f"Error setting up crypto directories: {str(e)}")
			return None


	def is_malware(self):
		"""These Yara rules are specialized for identifying well-known malware."""
		# Define directories
		rules_dir = "./App/yarascripts/YaraScan/rules/malware"
		compiled_dir = "./App/yarascripts/YaraScan/rules_compiled/malware"

		# Create full directory structure
		try:
			# Create both directories if they don't exist
			os.makedirs(rules_dir, exist_ok=True)
			os.makedirs(compiled_dir, exist_ok=True)
			
			# Only proceed if the rules directory has files
			if os.path.exists(rules_dir) and os.listdir(rules_dir):
				for n in os.listdir(rules_dir):
					rule_path = os.path.join(rules_dir, n)
					if not os.path.isdir(rule_path):
						try:
							compiled_path = os.path.join(compiled_dir, n)
							rule = yara.compile(rule_path)
							rule.save(compiled_path)
							rule = yara.load(compiled_path)
							m = rule.match(self.filename)
							if m:
								return m
						except Exception as e:
							print(f"Error processing rule {n}: {str(e)}")
							continue
			return None
							
		except Exception as e:
			print(f"Error setting up malware rules directories: {str(e)}")
			return None


	# Added by Yang
	def is_your_target(self,yara_file):
		compiled_dir = "./App/yarascripts/YaraScan/rules_compiled/your_target"
		
		# Create directory if it doesn't exist
		os.makedirs(compiled_dir, exist_ok=True)
		
		if os.path.isdir(yara_file):
			for n in os.listdir(yara_file):
				if not os.path.isdir(os.path.join(yara_file, n)):
					try:
						rule_path = os.path.join(yara_file, n)
						compiled_path = os.path.join(compiled_dir, n)
						
						rule = yara.compile(rule_path)
						rule.save(compiled_path)
						# Fix: Load from your_target directory instead of malware
						rule = yara.load(compiled_path)
						m = rule.match(self.filename)
						if m:
							return m
					except Exception as e:
						print(f"Error processing rule {n}: {str(e)}")
						continue
		elif os.path.isfile(yara_file):
			try:
				rule = yara.compile(yara_file)
				rule.save("./App/yarascripts/YaraScan/rules_compiled/your_target/" + yara_file)
				rule = yara.load("./App/yarascripts/YaraScan/rules_compiled/malware/" + yara_file)
				m = rule.match(self.filename)
				if m:
					return m
			except:
				pass
		else:
			return "[x] Wrong type of input!"

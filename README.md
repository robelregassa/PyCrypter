PyLoader
========

Proof of concept runtime encrypter for 32-bit portable executables in python.
Inspired by Hyperion(http://www.nullsecurity.net/papers/nullsec-pe-crypter.pdf) 
& Veil Framework(https://github.com/Veil-Framework)

Requirements
========
* [Python](https://www.python.org/)
* [PyCrypto](https://www.dlitz.net/software/pycrypto/)
* [py2exe](http://www.py2exe.org/)
* [pywin32](http://sourceforge.net/projects/pywin32/)
* [pefile](https://code.google.com/p/pefile/)
* [setuptools](https://pypi.python.org/pypi/setuptools)

Setup
========
* Install the required packages above
* Encrypt you loader using Veil's "python crypter"

> python pyherion.py loader.py loader_crypted.py

* Build your exe

> python setup.py

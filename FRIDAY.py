import pefile
import re
import os
import magic
import sys
#print ("Enter the hash name to inspect:")
hash_entry=raw_input("Enter the hash name to inspect:")
#print hash_entry
pathoffile='/root/Sample/'+hash_entry 
print " The sample exsists here" + ""+pathoffile
print ("\n")
whatisit=magic.from_file(pathoffile)
print hash_entry +""+" is a "+""+whatisit
print ("\n")


pe=pefile.PE(pathoffile)
for entry in pe.DIRECTORY_ENTRY_IMPORT:
	dll_name=entry.dll.decode('utf-8')
	if dll_name == "KERNEL32.dll":
		print("Kernel32.dll imports:")
                print ("\n")
	for func in entry.imports:
        	#print("\t%s at 0x%08x" % (func.name.decode('utf-8'), func.address))
                print ("\n")
		pattern=re.findall(r'GetTickCount |VirtualAlloc |LoadLibraryA |GetProcessHeap|VirtualFree|GetModuleHandleA|TerminateProcess|GetCurrentProcess|ExitProcess|FindNextFileA|FindFirstFileA|CloseHandle|VirtualAllocEx|VirtualFreeEx|WriteProcessMemory|CreateREmoteThread|CreateProcessA|GetThreadContext|NtUnmapViewOfSection|SuspendThread|GetThreadContext|SetThreadContext|LoadLibraryW|GetProcAddress|CreateToolhelp32Snapshot|Thread32Next|SetWindowsHookExa|UnhookWindowsHookEx|RegSetValueExA|FindWindowW|GetWindowLongA|VirtualProtect',str(func.name))
                if len(pattern) > 0:
                        print (" Process Injection Indicators and DLL combinations spotted:")
                        print ("\n")
			print  pattern
                        print ("\n")
                print("\t%s at 0x%08x" % (func.name, func.address))		#pattern2=re.findall(
path_file='strings /root/Sample/'+hash_entry+'> stinges.txt'
stringes=os.system(path_file)
#print stringes
file =open("stinges.txt","r")
item=file.readlines()
for i in range(0,len(item)):
	pattern2=re.findall(r'https?://[www.]?\w+.\w+.?\w+?[\/\w]*|www.\w+.\w?.?\w+[\/\w]*|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',item[i])
        pattern3=re.findall(r'stop|Sophos|SQLsafe|Symantec|McAfeeEngineService|vssadmin Delete Shadows /all /quiet',item[i])
        pattern4=re.findall(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$',item[i])
        if len(pattern3) >0:
                print pattern3
	if len(pattern2) > 0:
		print pattern2
        if len(pattern4) > 0:
                print pattern4
       
		

		

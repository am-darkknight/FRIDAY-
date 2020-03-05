import re
import pefile
import re
import os
import magic
import sys
#print ("Enter the hash name to inspect:")
hash_entry=raw_input("Enter the hash name to inspect:")
#print hash_entry
pathoffile='/home/remnux/Sample/'+hash_entry 
print " \033[1;31m"+'The sample exsists here' + ""+pathoffile
print ("\n")
whatisit=magic.from_file(pathoffile)
print hash_entry+'\033[1;31m' +""+" is a "+""+whatisit
print ("\n")


pe=pefile.PE(pathoffile)
for entry in pe.DIRECTORY_ENTRY_IMPORT:
	dll_name=entry.dll.decode('utf-8')
	if dll_name == "KERNEL32.dll":
		print("Kernel32.dll imports:")
                #print ("\n")
	for func in entry.imports:
        	#print("\t%s at 0x%08x" % (func.name.decode('utf-8'), func.address))
                #print ("\n")
		pattern=re.findall(r'GetTickCount |VirtualAlloc |LoadLibraryA |GetProcessHeap|VirtualFree|GetModuleHandleA|TerminateProcess|GetCurrentProcess|ExitProcess|FindNextFileA|FindFirstFileA|CloseHandle|VirtualAllocEx|VirtualFreeEx|WriteProcessMemory|CreateREmoteThread|CreateProcessA|GetThreadContext|NtUnmapViewOfSection|SuspendThread|GetThreadContext|SetThreadContext|LoadLibraryW|GetProcAddress|CreateToolhelp32Snapshot|Thread32Next|SetWindowsHookExa|UnhookWindowsHookEx|RegSetValueExA|FindWindowW|GetWindowLongA|VirtualProtect|CryptEncrypt',str(func.name))
                if len(pattern) > 0:
                        print ('\x1b[6;30;42m'+" Process Injection Indicators and DLL combinations spotted:"+'\x1b[0m')
                        #print ("\n")
			print  pattern
                        #print ("\n")
                #print("\t%s at 0x%08x" % (func.name, func.address))

path_file='strings /home/remnux/Sample/'+hash_entry+'> stinges.txt'
stringes=os.system(path_file)
file =open("stinges.txt","r")
with open('/home/remnux/Sample/stinges.txt', 'r') as f:
    for line in f:
	patterndomain=re.findall(r'https?://[www.]?\w+.\w+.?\w+?[\/\w]*|www.\w+.\w?.?\w+[\/\w]*|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',line)
	if len(patterndomain) > 0:
		print "Possible C2 Spotted"
		print patterndomain
	patternip=re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',line)
	if len(patternip) > 0:
		print "Possible C2 ip spotted "
		print patternip
	patternevasive=re.findall(r'stop|Sophos|SQLsafe|Symantec|McAfeeEngineService|vssadmin Delete Shadows /all /quiet',line)
	if len(patternevasive) > 0:
		print "Possible AV engine detection and uninstalling features spotted"
		print patternevasive
	
	if 'CryptEncrypt' in line:
		print "Ransomware function called:CryptEncrypt"
		#print ("\n")
	if 'GetTickCount' in line:
		print " Evasive Sandbox timer checker spotted: GetTickCount"
		#print ("\n")
	if 'HttpOpenRequestW' in line:
		print " Possible connection to a c2 domain via http: HttpOpenRequestW"
		#print ("\n")
	if 'GetThreadContext' in line:
		print "Possible Hollow process injection : GetThreadContext"
		#print ("\n")
		
	if 'SuspendThread'in line:
		print " Possible Suspend Inject Resume injection spotted: SuspendThread"
	if ' GetThreadContext' in line:
		print " Possible Suspend Inject Resume injection spotted: GetThreadContext"
	if 'SetThreadContext' in line:
		print " Possible Suspend Inject Resume injection spotted:SetThreadContext"
	if 'SetWindowsHookExA' in line:
		print "Possible Hook DLL injection spotted: SetWindowsHookExA"
	if 'RegSetValueExA' in line:
		print ' Possible malware persistence spotted: RegSetValueExA'
	
	
	
		
	

		


  

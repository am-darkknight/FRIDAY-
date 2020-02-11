# FRIDAY-
Friday is an intelligent engine that runs in a sandbox to dissect, extract IOC and run evasive sandbox malwares 


# WHY FRIDAY? 

1. Dynamic anaylsis of a sample and static analysis of a sample takes  a lot of time.

2. Researchers always would love to have some meteadata or indicators so that they are pace their investigations in the right areas.

3. Well, FRIDAY is here to do it. 


# WHAT DOES FRIDAY DO ? 

1. Friday indentifies the nature of the sample

2. Friday can predict 8 types of process injection techniques. 

3. Friday extracts IOCs like domain name and can compute what the strings in a file mean.

4. Friday also identifies evasive malware traits , process calls and can also give you a sneak peak what one should not have in a dynamic analysis machine. 

# HOW DO I RUN ? 

1. Create a folder for all your samples and the path must be /root/Sample/

2. Download FRIDAY.py and run it as " python FRIDAY.py"

3. Enter the hash of the file when it asks

4. Enjoy 


# Work in progress: 

1. Integration of Virus total API to look up the domains that the file calls out or has in strings 

2. Identification of type of packer.

3. WMI module that helps you to run a dynamic analysis and monitor windows machines that run malware remotely 


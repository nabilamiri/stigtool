from dotenv import load_dotenv
from nornir import InitNornir
from nornir.plugins.tasks import networking
from nornir.plugins.functions.text import print_result, print_title
from nornir.core.task import Result
from collections import defaultdict
import json
from lxml import etree
import os

# I have a .env file in the parent directory where I am loading my SSH user/pass credentials from. This loads them as environment variables.
load_dotenv()

nr = InitNornir(core={'num_workers': 50}, inventory={
    'plugin': 'nornir.plugins.inventory.simple.SimpleInventory',
    'options': {
        'host_file': 'inventory/hosts.yml',
        'group_file': 'inventory/groups.yml',
    }
}, logging={ 'enabled': False })

targetHosts = ['172.16.1.203', '172.16.1.204']

# This is taking a value from the Nornir inventory. Every host in the inventory has a variable named 'credentials' which contains either 'INTERNAL' or 'EXTERNAL'  The .env file contains the variables for both of those, named INTERNAL_NM_USER and INTERNAL_NM_PASS.
# 'task.host.username/password' is a well-known host variable that's automatically searched for credentials by NAPALM.
def populate_credentials(task):
    task.host.username = os.getenv('username')
    task.host.password = os.getenv('password')

def generate_config(task):
    # task.host['platform'] is a variable that I set in my inventory file on each host
    if task.host.get('platform') == 'ios':
        task.host['config'] = '''
no access-list 115
access-list 115 remark SSH Access to VTY
access-list 115 remark SSH Access for Net-EMC-230-PRICOL
access-list 115 permit ip host 128.149.4.93 any
access-list 115 remark SSH Access for Nettools-VM
access-list 115 permit ip host 137.78.254.188 any
access-list 115 remark SSH Access for Nettools-VM-New
access-list 115 permit ip host 128.149.4.192 any
access-list 115 remark SSH Access for Nettools2-VM
access-list 115 permit ip host 128.149.4.193 any
access-list 115 remark SSH Access for Net-EMC-230-PRICOL-NEW
access-list 115 permit ip host 128.149.4.91 any
access-list 115 remark SSH Access for Cisco Prime
access-list 115 permit ip host 128.149.4.191 any
access-list 115 remark SSH Access for DNA Center
access-list 115 permit ip host 137.78.143.70 any
access-list 115 deny ip any any log
'''

def collect_configurations(task):
    filtered_config = task.run(task=networking.napalm_get, name='Collecting full configuration',
    getters=["config"],
    retrieve="running")
    return filtered_config

# An inventory filter function is an easy way to explicitly choose the devices you want to run tasks on rather than trying to figure out a perfect combination of site/role/model/type, etc
def dev_switches(host):
    if host.hostname in targetHosts:
        return True
    else:
        return False

def line_by_line_comparison(existingConfiguration, linesToCompare, shouldExist, exactMatch=True):
    #run a comparison between your configDictionary and the check_content list
    #If we need to search for a term then we should pass in exactMatch=False during function call
    for key, values in existingConfiguration.items():
        for v in values:
            print("\nCurrently checking configuration for host", key)
            if shouldExist == False:
                for current_line in v:
                    for line in linesToCompare:
                        if line == current_line and exactMatch == True:
                            print("Issue found.", key, " contains", line, "Please remediate.")
                        if line in current_line and exactMatch == False:
                            print("Issue found.", key, " contains", line, "Please remediate.")
            #Check for single instance of a line within the configurations
            if shouldExist == True:
                for line in linesToCompare:
                        if line not in v:
                            print("Issue found ", line, " does not exist in configuration for host", key)

def CISC_L2_000010(existingConfiguration):
    #Description: The Cisco switch must be configured to disable non-essential capabilities.
    checkContent = [
    'boot network',
    'ip boot server',
    'ip bootp server',
    'ip dns server',
    'ip identd',
    'ip finger',
    'ip http server',
    'ip rcmd rcp-enable',
    'ip rcmd rsh-enable service config',
    'service finger'
    'service tcp-small-servers',
    'service udp-small-servers',
    'service pad'
    ]

    shouldExist = False
    print_title("CISC_L2_000010")
    line_by_line_comparison(existingConfiguration, checkContent, shouldExist)


def CISC_L2_000020(existingConfiguration):
    #Description: Verify if the switch configuration has 802.1x authentication implemented for all access switch ports connecting to LAN outlets (i.e., RJ-45 wall plates) or devices not located in the telecom room, wiring closets, or equipment rooms. MAC Authentication Bypass (MAB) must be configured on those switch ports connected to devices that do not support an 802.1x supplicant.
    print_title("CISC_L2_000020")
    hasBoth = 0 #this will keep a count per interface to see if both critieria are met
    for key, values in existingConfiguration.items():
        for v in values:
            print("\nCurrently checking configuration for host", key)
            for current_line in v:
                interface = current_line
                hasBoth = 0 #reset counter for hasBoth
                if interface.startswith("interface"):
                    #find the index position within the configuration to check for dot1x configuration
                    index_element = v.index(interface)
                    while v[index_element] != '!':
                        #for the comparison we are using a leading because the config contains a space for indentation
                        if v[index_element] == ' authentication port-control auto' or v[index_element] == ' dot1x pae authenticator':
                            hasBoth += 1 #increment if a match is found
                        if hasBoth == 2:
                            break
                        index_element += 1 #check the next line until reaching the end of interface configuration
                    if hasBoth < 2:
                        print(interface ,"is missing do1x configuration. Please remediate")

    #Verify 802.1x configuration on the switch
    checkContent = [
    'aaa new-model',
    'aaa group server radius',
    'server name',
    'aaa authentication do1x default group',
    'dot1x system-auth-control'
    ]

    shouldExist = True
    line_by_line_comparison(existingConfiguration, checkContent, shouldExist)


def CISC_L2_000030(existingConfiguration):
    #Description: The Cisco switch must authenticate all VLAN Trunk Protocol (VTP) messages with a hash function using the most secured cryptographic algorithm available.
    print_title("CISC_L2_000030")
    output = access_switches.run(task=networking.napalm_cli, commands=['show vtp password'])

    configDictionary = defaultdict(list)
    #build a datastructure with host: result pairings
    for h, l in zip(hostKeys, listOfKeys):
        filtered_output = output[l].result
        someString = filtered_output['show vtp password']
        if 'not configured' in someString:
            print("Host ", h,"does not have a VTP password. Please set one.")
        configDictionary[h].append(someString)
        filtered_output = None
        someString = None

def CISC_L2_000040(existingConfiguration):
    #Description: The Cisco switch must have STP Loop Guard enabled.
    qos = ['mls qos']
    shouldExist = True
    print_title("CISC_L2_000040")
    line_by_line_comparison(existingConfiguration, qos, shouldExist)

def CISC_L2_000090(existingConfiguration):
    #Description: The Cisco switch must have Root Guard enabled on all switch ports connecting to access layer switches and hosts.
    print_title("CISC_L2_000090")
    for key, values in existingConfiguration.items():
        for v in values:
            print("\nCurrently checking configuration for host", key)
            #reset both counters before checking for current host
            hasSwitchport = False
            hasSpanningTreeGuardRoot = False

            for current_line in v:
                interface = current_line
                hasBoth = 0 #reset counter for hasBoth
                if interface.startswith("interface"):
                    #find the index position within the configuration to check for dot1x configuration
                    index_element = v.index(interface)
                    while v[index_element] != '!':
                        #for the comparison we are using a leading because the config contains a space for indentation
                        #we have to check for routed ports and ignore those
                        if 'switchport' in v[index_element] and v[index_element] != ' no switchport':
                            hasSwitchport = True #increment if a match is found
                        if 'spanning-tree guard root' in v[index_element]:
                            hasSpanningTreeGuardRoot = True
                        if hasSwitchport == True and hasSpanningTreeGuardRoot == True:
                            break
                        index_element += 1 #check the next line until reaching the end of interface configuration
                    if hasSwitchport == True and hasSpanningTreeGuardRoot == False:
                        print(interface ,"is missing spanning-tree guard root command. Please remediate")

def CISC_L2_000100(existingConfiguration):
    #Description: The Cisco switch must have BPDU Guard enabled on all user-facing or untrusted access switch ports.
    print_title("CISC_L2_000100")
    for key, values in existingConfiguration.items():
        for v in values:
            print("\nCurrently checking configuration for host", key)
            for current_line in v:
                #reset both counters before checking for current host
                hasSwitchport = False
                hasBpduGuardEnable = False
                interface = current_line
                hasBoth = 0 #reset counter for hasBoth
                if interface.startswith("interface"):
                    #find the index position within the configuration to check for configuration
                    index_element = v.index(interface)
                    while v[index_element] != '!':
                        #for the comparison we are using a leading because the config contains a space for indentation
                        #we have to check for routed ports and ignore those
                        #we have to disqualify trunk ports
                        if 'switchport mode access' in v[index_element] and v[index_element] != ' no switchport':
                            hasSwitchport = True #increment if a match is found
                        if 'spanning-tree bpduguard enable' in v[index_element]:
                            hasBpduGuardEnable = True
                        if hasSwitchport == True and hasBpduGuardEnable == True:
                            break
                        index_element += 1 #check the next line until reaching the end of interface configuration
                    if hasSwitchport == True and hasBpduGuardEnable == False:
                        print(interface ,"is missing bpduguard enable command. Please remediate")

def CISC_L2_000110(existingConfiguration):
    #Description: The Cisco switch must have STP Loop Guard enabled.
    loopGuard = ['spanning-tree loopguard default']
    shouldExist = True
    print_title("CISC_L2_000110")
    line_by_line_comparison(existingConfiguration, loopGuard, shouldExist)

def CISC_L2_000120(existingConfiguration):
    #Description: The Cisco switch must have BPDU Guard enabled on all user-facing or untrusted access switch ports.
    print_title("CISC_L2_000120")
    for key, values in existingConfiguration.items():
        for v in values:
            print("\nCurrently checking configuration for host", key)
            for current_line in v:
                #reset both counters before checking for current host
                hasSwitchport = False
                hasSwitchportBlockUnicast = False
                interface = current_line
                hasBoth = 0 #reset counter for hasBoth
                if interface.startswith("interface"):
                    #find the index position within the configuration to check for configuration
                    index_element = v.index(interface)
                    while v[index_element] != '!':
                        #for the comparison we are using a leading because the config contains a space for indentation
                        #we have to check for routed ports and ignore those
                        #we have to disqualify trunk ports
                        if 'switchport mode access' in v[index_element] and v[index_element] != ' no switchport':
                            hasSwitchport = True #increment if a match is found
                        if 'switchport block unicast' in v[index_element]:
                            hasBpduGuardEnable = True
                        if hasSwitchport == True and hasSwitchportBlockUnicast == True:
                            break
                        index_element += 1 #check the next line until reaching the end of interface configuration
                    if hasSwitchport == True and hasSwitchportBlockUnicast == False:
                        print(interface ,"is missing switchport block unicast command. Please remediate")



def CISC_L2_000270(existingConfiguration):
    print_title("CISC_L2_000270")

    checkContent = [
    'native vlan'
    ]

    shouldExist = False
    exactMatch = False
    line_by_line_comparison(existingConfiguration, checkContent, shouldExist, exactMatch)

#def push_acl_config(task):
#    result = task.run(task=networking.napalm_configure, name='Loading config', configuration=task.host['config'], dry_run=False)
#    return Result(host=task.host, diff=result.diff, changed=result.changed)

# Select the devices from the inventory that you want to run tasks on
access_switches = nr.filter(filter_func=dev_switches)

# Run the task (python function) named populate_credentials on those devices
print_title('Populate credentials')
access_switches.run(task=populate_credentials)

# Generate a config snippet per device and save it in a host variable... In this case the config is the same for every device
#print_title('Generate ACL configuration for access switches')
#access_switches.run(task=generate_config)

# Actually send the config to the device. For IOS, NAPALM uses SCP and loads it in an atomic operation
#print_title('Deploy ACL configuration to access switches')
#result = access_switches.run(task=push_acl_config)

output = access_switches.run(task=collect_configurations)

#generate a list of all hosts
hostKeys = access_switches.inventory.hosts.keys()

#cast dictionary of keys to a list
listOfKeys = list(hostKeys)

print_title('Creating dictionary of lists')
configDictionary = defaultdict(list)

for h, l in zip(hostKeys, listOfKeys):
    filtered_output = output[l][1].result
    someString = filtered_output['config']['running']
    someString = someString.split('\n')
    configDictionary[h].append(someString)
    filtered_output = None
    someString = None

#access and print each line of the configuration
#for key, values in configDictionary.items():
#    for v in values:
#        print("The configuration for ", key, "is: ")
#        for i in v:
#            print(i)

CISC_L2_000010(configDictionary)
CISC_L2_000020(configDictionary)
CISC_L2_000030(configDictionary)
CISC_L2_000040(configDictionary)
CISC_L2_000090(configDictionary)
CISC_L2_000100(configDictionary)
CISC_L2_000110(configDictionary)
CISC_L2_000120(configDictionary)
CISC_L2_000270(configDictionary)

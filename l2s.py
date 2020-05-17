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

# You can increase or decrease number of hosts to run the test against by adding them here. 
targetHosts = ['172.16.1.213', '172.16.1.214']

# This is taking a value from the Nornir inventory. Every host in the inventory has a variable named 'credentials'.
# 'task.host.username/password' is a well-known host variable that's automatically searched for credentials by NAPALM.
def populate_credentials(task):
    task.host.username = os.getenv('username')
    task.host.password = os.getenv('password')

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

def lineByLineComparison(existingConfiguration, linesToCompare, shouldExist, test='not configured', exactMatch=True):
    #run a comparison between your configDictionary and the check_content list
    #If we need to search for a term then we should pass in exactMatch=False during function call
    for key, values in existingConfiguration.items():
        for v in values:
            if shouldExist == False:
                for current_line in v:
                    for line in linesToCompare:
                        if line == current_line and exactMatch == True:
                            testResult = "Issue found: " + key + " contains" + line + "Please remediate."
                            resultDictionary[h][test].append(testResult)
                        if line in current_line and exactMatch == False:
                            testResult = "Issue found: " + key + " contains" + line + "Please remediate."
                            resultDictionary[h][test].append(testResult)
            #Check for single instance of a line within the configurations
            if shouldExist == True:
                for line in linesToCompare:
                        if line not in v and exactMatch == True:
                            testResult = "Issue found: " + line + " does not exist in configuration for host " + key
                            resultDictionary[key][test].append(testResult)
                        if any(s.startswith(line) for s in v) == False and exactMatch == False:
                            testResult = "Issue found: " + line + " does not exist in configuration for host " + key
                            resultDictionary[key][test].append(testResult)

def checkInterface(existingConfiguration, lineToCompare, test):
        for key, values in existingConfiguration.items():
            for v in values:
                for current_line in v:
                    #reset both counters before checking for current host
                    hasSwitchport = False
                    hasLineToCompare = False
                    interface = current_line
                    hasBoth = 0 #reset counter for hasBoth
                    if interface.startswith("interface"):
                        #find the index position within the configuration to check for configuration
                        index_element = v.index(interface)
                        while v[index_element] != '!':
                            #for the comparison we are using a leading space because the config contains a space for indentation
                            #we have to check for routed ports and ignore those
                            #we have to disqualify trunk ports
                            if 'switchport mode access' in v[index_element] and v[index_element] != ' no switchport':
                                hasSwitchport = True #increment if a match is found
                            if lineToCompare in v[index_element]:
                                hasLineToCompare = True
                            if hasSwitchport == True and hasLineToCompare == True:
                                break
                            index_element += 1 #check the next line until reaching the end of interface configuration
                        if hasSwitchport == True and hasLineToCompare == False:
                            testResult = interface + " is missing " + lineToCompare +  " command. Please remediate"
                            resultDictionary[key][test].append(testResult)
def vlanParser(vlanList):
    activeVlans = []
    for vlan in vlanList:
        if '-' in vlan:
            t = vlan.split('-')
            activeVlans += range(int(t[0]), int(t[1]) + 1)
        else:
            activeVlans.append(int(vlan))
    #Let's remove duplicate entries in the list
    activeVlans = list(dict.fromkeys(activeVlans))
    return activeVlans

def CISC_L2_000010(existingConfiguration):
    #Description: The Cisco switch must be configured to disable non-essential capabilities.
    test = "CISC_L2_000010"
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
    print_title(test)
    lineByLineComparison(existingConfiguration, checkContent, shouldExist, test)

def CISC_L2_000020(existingConfiguration):
    #Description: Verify if the switch configuration has 802.1x authentication implemented for all access switch ports connecting to LAN outlets (i.e., RJ-45 wall plates) or devices not located in the telecom room, wiring closets, or equipment rooms. MAC Authentication Bypass (MAB) must be configured on those switch ports connected to devices that do not support an 802.1x supplicant.
    test = "CISC_L2_000020"
    print_title(test)
    hasBoth = 0 #this will keep a count per interface to see if both critieria are met
    for key, values in existingConfiguration.items():
        for v in values:
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
                        testResult = str(interface) + " is missing do1x configuration. Please remediate"
                        resultDictionary[key][test].append(testResult)

    #Verify 802.1x configuration on the switch
    checkContent = [
    'aaa new-model',
    'aaa group server radius',
    'server name',
    'aaa authentication do1x default group',
    'dot1x system-auth-control'
    ]

    shouldExist = True
    lineByLineComparison(existingConfiguration, checkContent, shouldExist, test)

def CISC_L2_000030(existingConfiguration):
    #Description: The Cisco switch must authenticate all VLAN Trunk Protocol (VTP) messages with a hash function using the most secured cryptographic algorithm available.
    test = "CISC_L2_000030"
    print_title(test)
    output = access_switches.run(task=networking.napalm_cli, commands=['show vtp password'])

    configDictionary = defaultdict(list)
    #build a datastructure with host: result pairings
    for h, l in zip(hostKeys, listOfKeys):
        filtered_output = output[l].result
        someString = filtered_output['show vtp password']
        if 'not configured' in someString:
            testResult = "Host " +  h + " does not have a VTP password. Please set one."
            resultDictionary[h][test].append(testResult)
        configDictionary[h].append(someString)
        filtered_output = None
        someString = None

def CISC_L2_000040(existingConfiguration):
    #Description: The Cisco switch must have STP Loop Guard enabled.
    qos = ['mls qos']
    shouldExist = True
    test = "CISC_L2_000040"
    print_title(test)
    lineByLineComparison(existingConfiguration, qos, shouldExist, test)

def CISC_L2_000090(existingConfiguration):
    #Description: The Cisco switch must have Root Guard enabled on all switch ports connecting to access layer switches and hosts.
    test = "CISC_L2_000090"
    print_title(test)
    commandToTest = 'spanning-tree guard root'
    checkInterface(existingConfiguration, commandToTest, test)

def CISC_L2_000100(existingConfiguration):
    #Description: The Cisco switch must have BPDU Guard enabled on all user-facing or untrusted access switch ports.
    test = "CISC_L2_000100"
    print_title(test)
    commandToTest = 'spanning-tree bpduguard enable'
    checkInterface(existingConfiguration, commandToTest, test)

def CISC_L2_000110(existingConfiguration):
    #Description: The Cisco switch must have STP Loop Guard enabled.
    loopGuard = ['spanning-tree loopguard default']
    shouldExist = True
    test = "CISC_L2_000110"
    print_title(test)
    lineByLineComparison(existingConfiguration, loopGuard, shouldExist, test)

def CISC_L2_000120(existingConfiguration):
    #Description: The Cisco switch must have BPDU Guard enabled on all user-facing or untrusted access switch ports.
    test = "CISC_L2_000120"
    print_title(test)
    commandToTest = 'switchport block unicast'
    checkInterface(existingConfiguration, commandToTest, test)

def CISC_L2_000130(existingConfiguration):
    #Description: The Cisco switch must have DHCP snooping for all user VLANs to validate DHCP messages from untrusted sources
    test = "CISC_L2_000130"
    print_title(test)
    vlansList = defaultdict(list)
    commandToTest = ['ip dhcp snooping']
    shouldExist = True
    exactMatch = False

    lineByLineComparison(existingConfiguration, commandToTest, shouldExist, test, exactMatch)

    for key, values in existingConfiguration.items():
        for v in values:
            for x in v:
                currentLine = x
                if currentLine.startswith("ip dhcp snooping"):
                    dhcpSnooping = True
                    tempString = currentLine.replace('ip dhcp snooping vlan ', '')
                    dhcpSnoopingVlans = tempString.split(',')
                    vlansList = vlanParser(dhcpSnoopingVlans)
                #collect current interface
                if currentLine.startswith("interface"):
                    interface = currentLine
                if currentLine.startswith(" switchport access vlan "):
                    filterString = currentLine.replace(' switchport access vlan ', '')
                    splitString = filterString.split(',')
                    vlansOnAccessInterface = vlanParser(splitString)
                    if (set(vlansOnAccessInterface).issubset(set(vlansList)) == False):
                        testResult = interface + " is an access interface with VLANs that are not being snooped. Please remediate."
                        resultDictionary[key][test].append(testResult)



def CISC_L2_000140(existingConfiguration):
    test = "CISC_L2_000140"
    print_title(test)
    commandToTest = 'ip verify source'
    checkInterface(existingConfiguration, commandToTest, test)

def CISC_L2_000150(existingConfiguration):
    #Description: The Cisco switch must have Dynamic Address Resolution Protocol (ARP) Inspection (DAI) enabled on all user VLANs.
    test = "CISC_L2_000130"
    print_title(test)
    vlansList = defaultdict(list)
    commandToTest = ['ip arp inspection']
    shouldExist = True
    exactMatch = False

    lineByLineComparison(existingConfiguration, commandToTest, shouldExist, test, exactMatch)

    for key, values in existingConfiguration.items():
        for v in values:
            for x in v:
                currentLine = x
                if currentLine.startswith("ip arp inspection"):
                    arpInspection = True
                    tempString = currentLine.replace('ip arp inspection vlan ', '')
                    arpInspectionVlans = tempString.split(',')
                    vlansList = vlanParser(arpInspectionVlans)
                #collect current interface
                if currentLine.startswith("interface"):
                    interface = currentLine
                if currentLine.startswith(" switchport access vlan "):
                    filterString = currentLine.replace(' switchport access vlan ', '')
                    splitString = filterString.split(',')
                    vlansOnAccessInterface = vlanParser(splitString)
                    if (set(vlansOnAccessInterface).issubset(set(vlansList)) == False):
                        testResult = interface + " is an access interface with VLANs that are not being inspected by Dynamic ARP Inspection. Please remediate."
                        resultDictionary[key][test].append(testResult)

def CISC_L2_000160(existingConfiguration):
    test = "CISC_L2_000160"
    print_title(test)
    commandToTest = 'storm-control unicast'
    checkInterface(existingConfiguration, commandToTest, test)
    commandToTest = 'storm-control broadcast'
    checkInterface(existingConfiguration, commandToTest, test)

def CISC_L2_000170(existingConfiguration):
    #Description: The Cisco switch must have IGMP or MLD Snooping configured on all VLANs.
    test = "CISC_L2_000170"
    print_title(test)
    commandToTest = ['no ip igmp snooping']
    shouldExist = False
    exactMatch = False
    lineByLineComparison(existingConfiguration, commandToTest, shouldExist, test, exactMatch)

def CISC_L2_000180(existingConfiguration):
    #Description: The Cisco switch must implement Rapid STP where VLANs span multiple switches with redundant links.
    test = "CISC_L2_000180"
    print_title(test)
    commandToTest = ['spanning-tree mode rapid-pvst']
    shouldExist = True
    lineByLineComparison(existingConfiguration, commandToTest, shouldExist, test)

def CISC_L2_000190(existingConfiguration):
    #Description: The Cisco switch must enable Unidirectional Link Detection (UDLD) to protect against one-way connections.
    test = "CISC_L2_000190"
    print_title(test)
    commandToTest = ['udld enable']
    shouldExist = True
    lineByLineComparison(existingConfiguration, commandToTest, shouldExist, test)

    #This will check on a per interface basis. We should consider modifying line by line to a boolean return...
    commandToTest = 'udld port'
    checkInterface(existingConfiguration, commandToTest, test)

def CISC_L2_000200(existingConfiguration):
    #Description: The Cisco switch must have all trunk links enabled statically.
    test = "CISC_L2_000200"
    print_title(test)
    output = access_switches.run(task=networking.napalm_cli, commands=['show interfaces switchport'])

    configDictionary = defaultdict(list)

    #build a datastructure with host: result pairings
    for h, l in zip(hostKeys, listOfKeys):
        filtered_output = output[l].result
        someString = filtered_output['show interfaces switchport']
        stringList = someString.split('\n')
        for x in stringList:
            if 'Name: ' in x:
                currentInterface = x
            if 'Negotiation of Trunking: On' in x:
                testResult = "Interface" + currentInterface + " on host " +  h + " is using auto negotiation of trunking. Please remediate."
                resultDictionary[h][test].append(testResult)

def CISC_L2_000210(existingConfiguration):
    #Description: The Cisco switch must have all disabled switch ports assigned to an unused VLAN.
    test = "CISC_L2_000210"
    print_title(test)
    output = access_switches.run(task=networking.napalm_cli, commands=['show interfaces switchport'])
    activeVlansOnHost = defaultdict(list)

    configDictionary = defaultdict(list)
    #Setting a flag to determine if TrunkAll is set. We need at least one VLAN disabled/not trunking to have an attempt at passing this rule
    trunkAll = False
    c = set()
    #build a datastructure with host: result pairings
    for l in hostKeys:
        filtered_output = output[l].result
        someString = filtered_output['show interfaces switchport']
        stringList = someString.split('\n')
        for x in stringList:
            activeVlans = []
            if 'Name: ' in x:
                currentInterface = x
            if 'Trunking VLANs Enabled: ALL' in x:
                testResult = "Interface" + currentInterface + " on host " +  l + " is trunking ALL VLANs. Please disable at least one VLAN."
                trunkAll = True
                resultDictionary[l][test].append(testResult)
                break
            if 'Trunking VLANs Enabled: ' in x and trunkAll == False:
                tempString = x.replace('Trunking VLANs Enabled: ', '')
                numbers = tempString.split(',')
                activeVlans = vlanParser(numbers)
                activeVlansOnHost[l] += activeVlans

    for key, values in existingConfiguration.items():
        for v in values:
            for current_line in v:
                interface = current_line
                if interface.startswith("interface"):
                        index_element = v.index(interface)
                        interfaceConfigurationBlock = []
                        vlansOnInterfaceConfiguration = []
                        while v[index_element] != '!':
                            currentLine = v[index_element]
                            interfaceConfigurationBlock.append(currentLine)
                            if 'switchport access vlan' in currentLine:
                                temporaryString = currentLine.replace(' switchport access vlan ', '')
                                remainingVlans = temporaryString.split(',')
                                vlansOnInterfaceConfiguration = vlanParser(remainingVlans)
                            index_element += 1

                        if ' switchport mode access' in interfaceConfigurationBlock and ' shutdown' in interfaceConfigurationBlock and (set(activeVlansOnHost[key]).intersection(set(vlansOnInterfaceConfiguration)) != c):
                            testResult = interface + " is shutdown in a VLAN that is in use. Please remediate"
                            resultDictionary[key][test].append(testResult)

def CISC_L2_000220(existingConfiguration):
    #Description: The Cisco switch must not have the default VLAN assigned to any host-facing switch ports.
    test = "CISC_L2_000220"
    print_title(test)
    output = access_switches.run(task=networking.napalm_cli, commands=['show vlan brief'])

    configDictionary = defaultdict(list)

    #build a datastructure with host: result pairings
    for h, l in zip(hostKeys, listOfKeys):
        filtered_output = output[l].result
        someString = filtered_output['show vlan brief']
        stringList = someString.split('\n')
        for x in stringList:
            if '1    default' in x:
                line = x
                tempString = " ".join(line.split())
                stringList = tempString.split(' ')
                #if the last element in the stringList array is a description rather than
                #an interface we know that no interfaces are assigned here
                if stringList[-1] == 'active' or stringList[-1] == 'inactive':
                    continue
                else:
                    testResult = stringList[-1] + " on host " +  h + " has access interfaces in the default VLAN. Please remediate."
                    resultDictionary[h][test].append(testResult)

def CISC_L2_000230(existingConfiguration):
    #Description: The Cisco switch must have the default VLAN pruned from all trunk ports that do not require it.
    test = "CISC_L2_000230"
    print_title(test)
    output = access_switches.run(task=networking.napalm_cli, commands=['show int trunk'])

    configDictionary = defaultdict(list)

    #build a datastructure with host: result pairings
    for h, l in zip(hostKeys, listOfKeys):
        filtered_output = output[l].result
        someString = filtered_output['show int trunk']
        stringList = someString.split('\n')
        for x in stringList:
            line = x
            if 'Vlans allowed on trunk' in line:
                index_element = stringList.index(line)
                index_element +=1 #iterate to the next line of the output which will contain ports and their allowed vlans on trunk
                while stringList[index_element].startswith('Port') == False:
                    currentLine = stringList[index_element]
                    interface = currentLine.split(' ') #grab the interface name
                    if('1,') in currentLine or ('1-') in currentLine: #check the current line for VLAN1 in the interface trunking
                        testResult = "VLAN1 is not being pruned from " + interface[0] + " on host " + h + ". Please remediate."
                        resultDictionary[h][test].append(testResult)
                    index_element +=1

def CISC_L2_000240(existingConfiguration):
    #Description: The Cisco switch must not use the default VLAN for management traffic.
    test = "CISC_L2_000240"
    print_title(test)

    for key, values in existingConfiguration.items():
        for v in values:
            for current_line in v:
                interface = current_line
                if interface == 'interface Vlan1':
                    #find the index position within the configuration to check for dot1x configuration
                    index_element = v.index(interface)
                    index_element += 1
                    if 'Management' or 'MGMT' in v[index_element]:
                        testResult = "The management VLAN is using VLAN1. Please remediate."
                        resultDictionary[key][test].append(testResult)        

def CISC_L2_000260(existingConfiguration):
    #Description: The Cisco switch must have the native VLAN assigned to an ID other than the default VLAN for all 802.1q trunk links.
    test = "CISC_L2_000260"
    print_title(test)
    output = access_switches.run(task=networking.napalm_cli, commands=['show interfaces switchport'])

    configDictionary = defaultdict(list)

    #build a datastructure with host: result pairings
    for h, l in zip(hostKeys, listOfKeys):
        filtered_output = output[l].result
        someString = filtered_output['show interfaces switchport']
        stringList = someString.split('\n')
        for x in stringList:
            if 'Name: ' in x:
                tempString = x
                currentInterface = tempString.replace("Name: ", '')
            if 'Trunking Native Mode VLAN: 1 (default)' in x:
                testResult = "Interface " + currentInterface + " on host " +  h + " is trunking the native VLAN. Please remediate."
                resultDictionary[h][test].append(testResult)

def CISC_L2_000270(existingConfiguration):
    #Description: The Cisco switch must not have any switchports assigned to the native VLAN.
    test = "CISC_L2_000270"
    print_title(test)
    checkContent = ['native vlan']
    shouldExist = False
    exactMatch = False
    lineByLineComparison(existingConfiguration, checkContent, shouldExist, test, exactMatch)

# Select the devices from the inventory that you want to run tasks on
access_switches = nr.filter(filter_func=dev_switches)

# Run the task (python function) named populate_credentials on those devices
print_title('Populate credentials')
access_switches.run(task=populate_credentials)
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

#Generate data structures (a dictionary of dictionary of lists) for the results to be captured
resultDictionary = defaultdict(dict)
for h in hostKeys:
    resultDictionary[h] = defaultdict(list)

CISC_L2_000010(configDictionary)
CISC_L2_000020(configDictionary)
CISC_L2_000030(configDictionary)
CISC_L2_000040(configDictionary)
CISC_L2_000090(configDictionary)
CISC_L2_000100(configDictionary)
CISC_L2_000110(configDictionary)
CISC_L2_000120(configDictionary)
CISC_L2_000130(configDictionary)
CISC_L2_000140(configDictionary)
CISC_L2_000150(configDictionary)
CISC_L2_000160(configDictionary)
CISC_L2_000170(configDictionary)
CISC_L2_000180(configDictionary)
CISC_L2_000190(configDictionary)
CISC_L2_000200(configDictionary)
CISC_L2_000210(configDictionary)
CISC_L2_000220(configDictionary)
CISC_L2_000230(configDictionary)
CISC_L2_000240(configDictionary)
#CISC-L2-000250 - All user facing ports cannot be trunk links
CISC_L2_000260(configDictionary)
CISC_L2_000270(configDictionary)

# Serializing json
json_object = json.dumps(resultDictionary, indent = 4)

# Writing to result.json
with open("results.json", "w") as outfile:
    outfile.write(json_object)
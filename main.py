#!/usr/bin/python

"""
./main.py [-s server_hostname] [-u username] [-p password] [-g GPFS version]
-s : hostname of the remote server to login to.
-u : username to user for login.
-p : Password to user for login.
-g : new GPFS version (e.g. 3.5.0.19)
"""

from __future__ import print_function

import os
import sys
import re
import getopt
import getpass
import pxssh

def exit_with_usage():
    print(globals()['__doc__'])
    sys.exit()


def getGpfsTarName(gpfsTarPath):
    head, tail = os.path.split(gpfsTarPath)

    gpfsTarName = re.sub('\n|\r', '', tail)
    return gpfsTarName


def getMainNodeName(system):
    system.sendline('hostname')
    system.prompt()

    # removing newline chars
    mainNodeName = re.sub('\n|\r', '', system.before.split("\n")[1])

    return mainNodeName


def checkArguments():
    ######################################################################
    ## Parse the options, arguments, get ready, etc.
    ######################################################################
    try:
        optlist, args = getopt.getopt(sys.argv[1:], 'h?s:u:p:g:', ['help','h','?'])
    except Exception as e:
        print(str(e))
        exit_with_usage()
    options = dict(optlist)
    if len(args) > 1:
        exit_with_usage()

    if [elem for elem in options if elem in ['-h','--h','-?','--?','--help']]:
        print("Help:")
        exit_with_usage()

    if '-s' in options:
        host = options['-s']
    else:
        host = raw_input('hostname: ')
    if '-u' in options:
        user = options['-u']
    else:
        user = raw_input('username: ')
    if '-p' in options:
        password = options['-p']
    else:
        password = getpass.getpass('password: ')
    if '-g' in options:
        gpfsVersion = options['-g']
    else:
        gpfsVersion = raw_input('gpfs version: ')
        # TODO: dodac sprawdzanie regexpem czy GPFS version jest w dobrym formacie?

    return host, user, password, gpfsVersion


def systemPreCheck(system, gpfs):
    print("\nChecking if the correct GPFS tar file is in /tmp... -> ", end="")
    system.sendline('find /tmp -maxdepth 1 -name GPFS-%s-*' %gpfs)
    system.prompt()
    findTarFileOutput = system.before.split("\n")[1:]
    findTarFileOutput = [entry for entry in findTarFileOutput if entry]
    if findTarFileOutput:
        print("OK")
        for file in findTarFileOutput:
            print("GPFS tar file has been found: " + file)
            gpfsTarName = getGpfsTarName(file)
    else:
        print("FAIL")
        sys.exit("ERROR: Can't find GPFS tar (for version: %s) in /tmp. Check it manually." % gpfs)

    print("\nChecking if there is cs_gpfs_ls_check script in /tmp... -> ", end="")
    system.sendline('find /tmp -maxdepth 1 -name cs_gpfs_ls_check')
    system.prompt()
    findCSCheckOutput = system.before.split("\n")[1:]
    findCSCheckOutput = [entry for entry in findCSCheckOutput if entry]

    if findCSCheckOutput:
        print("OK")
        for file in findCSCheckOutput:
            print("Script cs_gpfs_ls_check has been found: " + file)
    else:
        print("FAIL")
        sys.exit("ERROR: Can't find cs_gpfs_ls_check in /tmp. Check it manually & correct it.")


def checkCurrentGPFSVersion(system):
    print("\nChecking currently installed GPFS version ...")
    system.sendline("mmdsh 'mmfsadm dump version | grep Build'")
    system.prompt()
    checkGPFSVersionOutput = system.before.split("\n")[1:]
    # mmfsadm dump version | grep Build | awk -F \" '{print $2}' | sed 's/ /_/g'
    checkGPFSVersionOutput = [entry for entry in checkGPFSVersionOutput if entry]
    for node in checkGPFSVersionOutput:
        print(node)

    pass


def checkIfFileExists(system):
    pass


def checkIfNodesAreActive(system):

    activeNodeList = {}

    print("\nChecking if all nodes are active...")
    system.sendline("mmgetstate -a")
    system.prompt()

    # TODO: jak lepiej sprasowac ten output komendy mmgetstate -a ?
    mmgetstateOutput = system.before.splitlines()[4:]
    # TODO: uzyc tego splitlines w pozostalych przypadkach

    try:
        for line in mmgetstateOutput:
            if line.split()[2] == 'active':
                tmpNodeName = line.split()[1]
                activeNodeList[tmpNodeName] = True
            else:
                tmpNodeName = line.split()[1]
                activeNodeList[tmpNodeName] = False
    except IndexError, error:
        print("\nERROR: " + str(error))

    # TODO: sprawdzic negatywny scenariusz, gdy jeden node nie jest active
    for nodeState in activeNodeList:
        if not nodeState:
            print("FAIL!\nERROR: One or more nodes are not active.")
            sys.exit(activeNodeList)
        else:
            print(nodeState + " : " + "OK")


def disableTraces(system):

    print("\nDisabling all active traces... -> ", end='')
    system.sendline("mmtracectl --stop;mmtracectl --off")
    system.prompt()

    expectedAnswer = "mmchconfig: Command successfully completed"
    mmTraceCtlOutput = system.before.splitlines()[1:]

    if mmTraceCtlOutput[0] == expectedAnswer:
        system.sendline('mmdsh "ps -ef|grep lxtrace|grep -v grep| grep -v ssh|sort"')
        system.prompt()
        tmpCmdOutput = system.before.splitlines()[1:]
        # if there is no answer it's OK
        if not tmpCmdOutput:
            print("OK")
        else:
            print("FAIL!\nERROR:Some traces are still active")
            for line in tmpCmdOutput:
                print(line)
            sys.exit()
    else:
        print("FAIL!\nERROR:Can't stop traces.")
        for line in mmTraceCtlOutput:
            print(line)
        sys.exit()


def saveMmlsxxOutput(system):
    print("\nExecuting cs_gpfs_ls_check script ... -> ", end='')
    system.sendline("cd /tmp; ./cs_gpfs_ls_check")
    system.prompt()

    cmdOutput = system.before.splitlines()[1:]

    if re.search(r'mmcheck[\.\d]+_ saved\.', cmdOutput[0]):
        print("OK")
        print("\nChecking if a file with mmlsxx commands has been created... -> ", end='')
        system.sendline("find /tmp -name mmcheck.*_")
        system.prompt()
        findMmcheckOutput = system.before.splitlines()[1:]
        if findMmcheckOutput[0]:
            print("OK")
            print("Mmmlsxx commands have been saved: " + findMmcheckOutput[0])
        else:
            print("FAIL\nERROR: Expected file (mmcheck*) has not been created.")
            sys.exit()
    else:
        print("FAIL\nERROR: cs_gpfs_ls_check has not been executed properly.")
        sys.exit()


def createInstallDir(system, gpfs):
    print("\nCreating a new installation directory... -> ", end='')
    system.sendline("mkdir /tmp/GPFS.%s"%gpfs)
    system.prompt()

    mkdirOutput = system.before.splitlines()[1:]

    if not mkdirOutput:
        system.sendline("find /tmp -name GPFS.%s"%gpfs)
        system.prompt()
        findGpfsDirOutput = system.before.splitlines()[1:]
        if not findGpfsDirOutput:
            print("OK")
            print("Install dir has been created: " + findGpfsDirOutput)
        else:
            print("FAIL\n")
            sys.exit()
            # TODO: dodac info co za fail i dlaczego
    else:
        print("FAIL")
        for line in mkdirOutput:
            print("ERROR: " + line)
        sys.exit()

if __name__ == "__main__":

    host, user, password, gpfsVersion = checkArguments()

    try:
        cs = pxssh.pxssh()
        print("\n\nSSH-ing to ETERNUS CS (%s)..." % host)
        cs.login(host,user,password)
        systemPreCheck(cs, gpfsVersion)
        targetNode = getMainNodeName(cs)
        checkCurrentGPFSVersion(cs)
        checkIfNodesAreActive(cs)
        #disableTraces(cs)
        #saveMmlsxxOutput(cs)
        createInstallDir(cs, gpfsVersion)

        print("\n===== THE END ======\n")

    except pxssh.ExceptionPxssh, error:
        print("## pxssh failed on login.")
        print(str(error))


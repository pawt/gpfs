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
import time
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

    findTarFileOutput = system.before.splitlines()[1:]

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
    findCSCheckOutput = system.before.splitlines()[1:]

    if findCSCheckOutput:
        print("OK")
        for file in findCSCheckOutput:
            print("Script cs_gpfs_ls_check has been found: " + file)
    else:
        print("FAIL")
        sys.exit("ERROR: Can't find cs_gpfs_ls_check in /tmp. Check it manually & correct it.")

    return gpfsTarName

def checkCurrentGPFSVersion(system):
    print("\nChecking currently installed GPFS version...")
    system.sendline("mmdsh 'mmfsadm dump version | grep Build'")
    system.prompt()
    checkGPFSVersionOutput = system.before.splitlines()[1:]
    # mmfsadm dump version | grep Build | awk -F \" '{print $2}' | sed 's/ /_/g'

    for node in checkGPFSVersionOutput:
        print(node)


def checkIfFileExists(system):
    #TODO: fill this function
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

    return activeNodeList.keys() # returns the list of all nodes names


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
    print("\nExecuting cs_gpfs_ls_check script... -> ", end='')
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
            print("Mmmlsxx commands saved: " + findMmcheckOutput[0])
        else:
            print("FAIL\nERROR: Expected file (mmcheck*) has not been created.")
            sys.exit()
    else:
        print("FAIL\nERROR: cs_gpfs_ls_check has not been executed properly.")
        sys.exit()


def createInstallDir(system, gpfs):
    print("\nCreating a new installation directory on all nodes... -> ", end='')
    system.sendline('mmdsh "mkdir /tmp/GPFS.%s"' % gpfs)
    system.prompt()

    mkdirOutput = system.before.splitlines()[1:]

    # TODO: dopracowac sprawdzanie czy ten katalog pojawil sie na wszystkich node'ach

    if not mkdirOutput:
        system.sendline('mmdsh "find /tmp -name GPFS.%s"' % gpfs)
        system.prompt()

        findGpfsDirOutput = system.before.splitlines()[1:]

        if findGpfsDirOutput:
            installDirPath = findGpfsDirOutput[0].split()[1]
            print("OK")
            for node in findGpfsDirOutput:
                print("Install dir created on " + node)
            return installDirPath
        else:
            print("FAIL")
            for line in findGpfsDirOutput:
                print("ERROR: " + line)
            sys.exit()
    else:
        print("FAIL")
        for line in mkdirOutput:
            print("ERROR: " + line)
        sys.exit()



def copyGPFSTarFile(system, tarName, installDir, targetNode):
    print("\nCopying tar file on main mode (%s)... -> " % targetNode, end='')

    system.sendline("cp /tmp/%s %s/." % (tarName, installDir))
    system.prompt()

    cpTarOutput = system.before.splitlines()[1:]

    if not cpTarOutput:
        system.sendline("find %s -name %s" % (installDir, tarName))
        system.prompt()
        findGpfsTarOutput = system.before.splitlines()[1:]
        if findGpfsTarOutput:
            print("OK")
            print("Tar file copied: " + findGpfsTarOutput[0])
        else:
            print("FAIL")
            sys.exit("ERROR:Can't find %s/%s . Check it manually." % (installDir, tarName))
    else:
        print("FAIL")
        for line in cpTarOutput:
            print("ERROR: " + line)
        sys.exit()

def distributeGPFSTarFile(system, targetNode, installDir, tarName, nodeList):

    print("\nCopying tar file to all nodes... -> ", end='')
    system.sendline('mmdsh "scp -p {0}:{1}/{2} {1}/. |sort"'.format(targetNode, installDir, tarName))
    system.prompt()

    system.sendline('mmdsh "find {0} -name {1}"'.format(installDir, tarName))
    system.prompt()

    # TODO: dopracowac sprawdzanie czy ten plik pojawil sie na wszystkich node'ach?

    findDistributedTarOutput = system.before.splitlines()[2:]

    if len(findDistributedTarOutput) == len(nodeList):
        print("OK")
        for node in findDistributedTarOutput:
            print("GPFS tar copied to " + node)
    else:
        if not findDistributedTarOutput:
            print("FAIL\nERROR: Can't find copied GPFS tar on any node. Check it manually.")
        else:
            print("FAIL\nERROR: Can't find copied GPFS tar on ALL nodes. Only on the following: ")
            for line in findDistributedTarOutput:
                print(line)
        print("\nThe full list of nodes: " + str(nodeList))
        sys.exit()

def unpackGPFSTar(system, installDir, tarName):
    print("\nUnpacking GPFS tar file on all nodes... -> ", end='')
    system.sendline('mmdsh "cd %s; tar xfz %s | sort"' % (installDir, tarName))
    system.prompt()

    tarOutput = system.before.splitlines()[2:]

    if not tarOutput:
        print("OK")
    else:
        print("FAIL")
        for line in tarOutput:
            print("ERROR: " + line)
        sys.exit()

def stoppingCSandGPFS(system):
    print("\nStopping CS & GPFS on all nodes: ")
    system.sendline('vtcon stop')
    system.prompt(timeout=60)

    vtconStopOutput = system.before.splitlines()[1:]

    if not vtconStopOutput:
        system.sendline('vtinfo')
        system.prompt()
        vtinfoOutput = system.before.splitlines()[5:]
        if not vtinfoOutput:
            print("OK : CS and GPFS on all nodes are stopped")
        else:
            print("ERROR : Some processes are still running:")
            for line in vtinfoOutput:
                print(line)
            sys.exit()
    else:
        print("FAIL")
        for line in vtconStopOutput:
            print("ERROR: " + line)
        sys.exit()

if __name__ == "__main__":

    host, user, password, gpfsVersion = checkArguments()

    try:
        cs = pxssh.pxssh()
        fout = file('/tmp/gpfs_autoinstall.log', 'w')
        cs.logfile = fout

        print("\n\nSSH-ing to ETERNUS CS (%s)..." % host)
        cs.login(host,user,password)
        gpfsTarFileName  = systemPreCheck(cs, gpfsVersion)
        targetNode = getMainNodeName(cs)
        checkCurrentGPFSVersion(cs)
        # TODO: Add question "Do you really want to install GPFS version + gpfsVersion"
        nodesList = checkIfNodesAreActive(cs)
        #disableTraces(cs)
        #saveMmlsxxOutput(cs)
        #installDirPath = createInstallDir(cs, gpfsVersion)
        installDirPath = "/tmp/GPFS.3.5.0.19"
        copyGPFSTarFile(cs,gpfsTarFileName,installDirPath, targetNode)

        if len(nodesList) != 1:
            distributeGPFSTarFile(cs, targetNode, installDirPath, gpfsTarFileName, nodesList)

        unpackGPFSTar(cs, installDirPath, gpfsTarFileName)

        stoppingCSandGPFS(cs)

        print("\n===== THE END ======\n")

    except pxssh.ExceptionPxssh, error:
        print("## pxssh failed on login.")
        print(str(error))


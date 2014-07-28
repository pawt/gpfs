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
import pexpect


LOG_FILE_PATH = "/tmp/gpfs_autoinstall.log"


def exit_with_usage():
    print(globals()['__doc__'])
    sys.exit()


def query_yes_no(question, default=None):
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is one of "yes" or "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}

    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            print("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")


def getGpfsTarName(gpfsTarPath):
    head, tail = os.path.split(gpfsTarPath)

    gpfsTarName = re.sub('\n|\r', '', tail)
    return gpfsTarName


def getMainNodeName(system):
    system.sendline('hostname')
    system.prompt()

    return system.before.splitlines()[1].lower()


def extractNodeTypes(fullNodesList):
    icpList = []
    idpList = []

    for node in fullNodesList:
        if re.search(r'ICP[\d]+', node, re.IGNORECASE):
            icpList.append(node)
        elif re.search(r'IDP[\d]+', node, re.IGNORECASE):
            idpList.append(node)

    return icpList, idpList


def checkArguments():
    ######################################################################
    ## Parse the options, arguments, get ready
    ######################################################################

    try:
        optlist, args = getopt.getopt(sys.argv[1:], 'h?s:u:p:g:', ['help', 'h', '?'])
    except Exception as e:
        print(str(e))
        exit_with_usage()

    options = dict(optlist)

    if len(args) > 1:
        exit_with_usage()

    if [elem for elem in options if elem in ['-h', '--h', '-?', '--?', '--help']]:
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
        gpfsVersion = raw_input('gpfs version (e.g. 3.5.0.19): ')
        while True:
            if re.search(r'(\d\.){3}\d+', gpfsVersion):
                print("GPFS format OK")
                break
            else:
                print("ERROR : Incorrect GPFS version format. Reenter GPFS version you want to install.")
                gpfsVersion = raw_input('gpfs version (e.g. 3.5.0.19): ')

    return host, user, password, gpfsVersion


def systemPreCheck(system, gpfs):
    print("\nChecking if the correct GPFS tar file is in /tmp...")
    system.sendline('find /tmp -maxdepth 1 -name GPFS-%s-*' % gpfs)
    system.prompt()

    findTarFileOutput = system.before.splitlines()[1:]

    if findTarFileOutput:
        for file in findTarFileOutput:
            print("OK : GPFS tar file has been found: " + file)
            gpfsTarName = getGpfsTarName(file)
    else:
        sys.exit("FAIL : Can't find GPFS tar (for version: %s) in /tmp. Check it manually." % gpfs)

    print("\nChecking if there is cs_gpfs_ls_check script in /tmp...")
    system.sendline('find /tmp -maxdepth 1 -name cs_gpfs_ls_check')
    system.prompt()
    findCSCheckOutput = system.before.splitlines()[1:]

    if findCSCheckOutput:
        for file in findCSCheckOutput:
            print("OK : Script cs_gpfs_ls_check has been found: " + file)
    else:
        sys.exit("FAIL : Can't find cs_gpfs_ls_check in /tmp. Check it manually & correct it.")

    return gpfsTarName


def checkCurrentGPFSVersion(system):
    print("\nChecking currently installed GPFS version...")
    # system.sendline("mmdsh 'mmfsadm dump version | grep Build'")
    system.sendline('mmfsadm dump version | grep Build | awk -F \\" \'{print $2}\' | sed \'s/ /_/g\'')
    system.prompt()
    checkGPFSVersionOutput = system.before.splitlines()[2:]

    if re.search(r'[\d._]+', checkGPFSVersionOutput[0]):
        print("Current GPFS version: " + checkGPFSVersionOutput[0])
    else:
        print("FAIL:")
        for line in checkGPFSVersionOutput:
            print(line)
        sys.exit()

def checkIfNodesAreActive(system):
    activeNodeList = {}

    print("\nChecking GPFS state on all nodes...")
    system.sendline("mmgetstate -a")
    system.prompt()

    mmgetstateOutput = system.before.splitlines()[4:]

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

    for nodeState in activeNodeList:
        if not activeNodeList[nodeState]:
            print("FAIL : GPFS on one or more nodes is not active:")
            for line in mmgetstateOutput:
                print(line)
            sys.exit()
        else:
            print(nodeState + " : " + "OK")

    return [node.lower() for node in activeNodeList.keys()]  # returns the list of all nodes names


def disableTraces(system):
    print("\nDisabling all active traces...")
    system.sendline("mmtracectl --stop;mmtracectl --off")
    system.prompt()

    expectedAnswer = "mmchconfig: Command successfully completed"
    mmTraceCtlOutput = system.before.splitlines()[1:]

    if mmTraceCtlOutput[0] == expectedAnswer:
        system.sendline('mmdsh "ps -ef|grep lxtrace|grep -v grep| grep -v ssh"| sort')
        system.prompt()
        tmpCmdOutput = system.before.splitlines()[1:]
        # if there is no answer it's OK
        if not tmpCmdOutput:
            print("OK : Traces disabled.")
        else:
            print("FAIL\nERROR : Some traces are still active")
            for line in tmpCmdOutput:
                print(line)
            sys.exit()
    else:
        print("FAIL\nERROR : Can't stop traces.")
        for line in mmTraceCtlOutput:
            print(line)
        sys.exit()


def saveMmlsxxOutput(system):
    print("\nExecuting cs_gpfs_ls_check script...")
    system.sendline("chmod 722 /tmp/cs_gpfs_ls_check; cd /tmp; ./cs_gpfs_ls_check")
    system.prompt(timeout=30)

    cmdOutput = system.before.splitlines()[1:]

    try:
        if re.search(r'mmcheck[\.\d]+_ saved\.', cmdOutput[0]):
            print("OK : cs_gpfs_]ls_check executed.")
            print("\nChecking if a file with mmlsxx commands has been created...")
            system.sendline("find /tmp -name mmcheck.*_")
            system.prompt()
            findMmcheckOutput = system.before.splitlines()[1:]
            if findMmcheckOutput[0]:
                print("OK : Mmmlsxx commands saved: " + findMmcheckOutput[0])
            else:
                sys.exit("FAIL : Expected file (mmcheck*) has not been created.")
        else:
            print("FAIL : Something went wrong with running cs_gpfs_ls_check:")
            for line in cmdOutput:
                print(line)
            sys.exit()
    except IndexError, error:
        print("\nERROR: " + str(error))


def createInstallDir(system, gpfs):
    print("\nCreating a new installation directory on all nodes... -> ", end='')
    system.sendline('mmdsh "mkdir /tmp/GPFS.%s"' % gpfs)
    system.prompt()

    mkdirOutput = system.before.splitlines()[1:]

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
            for line in findGpfsDirOutput:
                print("ERROR: " + line)
            sys.exit()
    else:
        print("FAIL")
        for line in mkdirOutput:
            print("ERROR: " + line)
        sys.exit()


def copyGPFSTarFile(system, tarName, installDir, targetNode):
    print("\nCopying tar file on main mode (%s)..." % targetNode)
    system.sendline("cp /tmp/%s %s/." % (tarName, installDir))
    system.prompt()

    cpTarOutput = system.before.splitlines()[1:]

    if not cpTarOutput:
        system.sendline("find %s -name %s" % (installDir, tarName))
        system.prompt()
        findGpfsTarOutput = system.before.splitlines()[1:]
        if findGpfsTarOutput:
            print("OK : Tar file copied: " + findGpfsTarOutput[0])
        else:
            sys.exit("FAIL : Can't find %s/%s . Check it manually." % (installDir, tarName))
    else:
        for line in cpTarOutput:
            print("FAIL: " + line)
        sys.exit()


def distributeGPFSTarFile(system, targetNode, installDir, tarName, nodeList):
    print("\nCopying tar file to all nodes...")
    system.sendline('mmdsh "scp -p {0}:{1}/{2} {1}/. "| sort'.format(targetNode, installDir, tarName))
    system.prompt()

    system.sendline('mmdsh "find {0} -name {1}"'.format(installDir, tarName))
    system.prompt()

    findDistributedTarOutput = system.before.splitlines()[2:]

    if len(findDistributedTarOutput) == len(nodeList):
        for node in findDistributedTarOutput:
            print("OK : GPFS tar copied to " + node)
    else:
        if not findDistributedTarOutput:
            print("FAIL : Can't find copied GPFS tar on any node. Check it manually.")
        else:
            print("FAIL : Can't find copied GPFS tar on ALL nodes. Only on the following: ")
            for line in findDistributedTarOutput:
                print(line)
        print("\nThe full list of nodes: " + str(nodeList))
        sys.exit()


def unpackGPFSTar(system, installDir, tarName):
    print("\nUnpacking GPFS tar file on all nodes...")
    system.sendline('mmdsh "cd %s; tar xfz %s"| sort' % (installDir, tarName))
    system.prompt()

    tarOutput = system.before.splitlines()[2:]

    if not tarOutput:
        print("OK : %s unpacked on all nodes in dir %s" % (tarName, installDir))
    else:
        for line in tarOutput:
            print("FAIL: " + line)
        sys.exit()


def stoppingCSProcesses(system):
    print("\nStopping CS processes on all nodes:")
    system.sendline('vtcon stop')
    system.prompt(timeout=60)  # vtcon stop command needs longer timeout

    vtconStopOutput = system.before.splitlines()[1:]

    if not vtconStopOutput:
        system.sendline('vtinfo')
        system.prompt()
        vtinfoOutput = system.before.splitlines()[5:]
        if not vtinfoOutput:
            print("OK : CS processes on all nodes are stopped")
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


def stoppingHSMDaemons(system):
    # TODO: this procedure should be tested in negative scenario
    print("\nChecking if there are any HSM daemons running...")
    system.sendline('mmdsh "ps -ef| grep dsm|grep -v grep|grep -v ssh"| sort')
    system.prompt()
    grepDsmOutput = system.before.splitlines()[1:]

    if grepDsmOutput:
        print("There are some HSM daemons that need to be stopped:")
        for line in grepDsmOutput:
            print(line)

        userDecision = query_yes_no("\nDo you want to stop all these HSM daemons?")

        if userDecision:
            print("\nStopping HSM daemons...")
            # TODO: this part has not been tested (use KAUZI?)
            system.sendline('mmdsh "dsmmigfs stop"')
            system.prompt(timeout=60)
            dsmmigfsOutput = system.before.splitlines()[1:]
            # TODO: IMPORTANT: depending on the output of dsmmigfs top command - do something
        else:
            sys.exit("## Script has been aborted by the user. ##")
    else:
        print("OK : There are no HSM daemons running on any node.")


def unmountingInstall2000(system):
    print("\nUnmounting directory /install2000...")

    # unmounting /install2000 on all nodes
    system.sendline('mmdsh "instfs stop"')
    system.prompt()

    # confirming that /install2000 has been unmounted on all nodes
    system.sendline('mmdsh "less /proc/mounts | grep install2000"')
    system.prompt()

    grepInstall2000Output = system.before.splitlines()[1:]

    if not grepInstall2000Output:
        print("OK : /install2000 unmounted.")
    else:
        print("FAIL: /install2000 is still mounted on some nodes:")
        for line in grepInstall2000Output:
            print(line)
        sys.exit()


def stoppingNfsServer(system):
    # TODO: needs to be tested on multiNode system
    print("\nStopping nfsserver on all nodes...")

    # stopping nfsserver on all nodes
    system.sendline('mmdsh "/etc/init.d/nfsserver stop"')
    system.prompt()

    stopNfsserverOutput = system.before.splitlines()[1:]

    for line in stopNfsserverOutput:
        print(line)


def unmountingFileSystems(system):
    # TODO: needs to be tested on multiNode system
    print("\nUnmounting file systems on all nodes...")
    system.sendline('mmumount all -a')
    system.prompt()
    mmumountOutput = system.before.splitlines()[1:]

    # confirming that all file systems have been unmounted
    system.sendline('mmdsh "less /proc/mounts | grep gpfs"')
    system.prompt()

    grepMountsOutput = system.before.splitlines()[1:]

    if not grepMountsOutput:
        print("OK : Unmounting completed successfully.")
    else:
        print("FAIL : Can't unmount all file systems on some nodes:  ")
        for line in mmumountOutput:
            print(line)
        sys.exit()


def unloadKernelModules(system):
    # TODO: needs to be tested on multiNode system
    unloadSuccessful = True

    print("\nUnloading all kernel modules on all nodes...")
    system.sendline('cafs_stop -a')
    system.prompt(timeout=30)

    cafsStopOutput = system.before.splitlines()[1:]

    # checking if output of cafs_stop command has some errors/problems with unloading
    for line in cafsStopOutput:
        if re.search(r'ERROR', line) or re.search(r'busy', line):
            unloadSuccessful = False
            print("\nFAIL : Cafs_stop -a has some problems with unloading:\n")
            for line in cafsStopOutput:
                print(line)
            sys.exit()

    if unloadSuccessful:
        print("OK : Kernel modules unloaded successfully.")


def installGPFSOnTargetNode(system, targetNode, installDirPath):
    print("\nInstalling a new GPFS on the main node (%s)..." % targetNode)
    system.sendline('rpm -Uhv %s/*.rpm' % installDirPath)
    system.prompt()

    print("OK : Installation completed on node %s" % targetNode)

    system.sendline('rpm -qa | grep -i gpfs')
    system.prompt()

    rmpQaGrepOutput = system.before.splitlines()[1:]

    print("\nCurrently installed packages:")
    for line in rmpQaGrepOutput:
        print(line)

    print("\nPlease check if the correct packages have been installed.")


def compileCompatibillityLayerOnTargetNode(system, targetNode):
    print("\nCompiling compatibility layer on the main node (%s)..." % targetNode)
    system.sendline('export SHARKCLONEROOT=/usr/lpp/mmfs/src; \
                    cd /usr/lpp/mmfs/src; make Autoconfig; make World; make InstallImages;echo $?')
    system.prompt()

    exportCmdResult = system.before.splitlines()[-1]

    if exportCmdResult[-1] == "0":
        print("OK: Compilation completed successfully.")
    else:
        print("FAIL : Compilation failed. See /tmp/gpfs_autoinstall.log for details.\n")
        sys.exit()


def checkFilesAfterCompilationOnTargetNode(system):
    allFilesExist = True

    print("\nChecking if the proper files have been created after compilation...")
    commandsToBeChecked = ["ls -l /usr/lpp/mmfs/bin/lxtrace-`uname -r`",
                           "ls -l /usr/lpp/mmfs/bin/kdump-`uname -r`",
                           "ls -l /lib/modules/`uname -r`/extra/mmfs26.ko",
                           "ls -l /lib/modules/`uname -r`/extra/mmfslinux.ko",
                           "ls -l /lib/modules/`uname -r`/extra/tracedev.ko"]

    for cmd in commandsToBeChecked:
        system.sendline(cmd + "| awk \'{print $1 $6, $7, $8, $9, $10}\' ; echo $?")
        system.prompt()
        cmdOutput = system.before.splitlines()[1:]
        if cmdOutput[-1] == "0":
            print("OK : " + cmdOutput[0])
        else:
            print("FAIL : " + cmdOutput[0])
            allFilesExist = False

    if not allFilesExist:
        sys.exit("\nFAIL : Can't find some mandatory files (see above). Aborting.\n")


def installGPFSOnAllNodes(system, nodesList, installDirPath):
    #TODO: needs to be tested on multiNode system
    nodesString = ",".join(nodesList)
    print("\nPreparing the GPFS installation on the rest of the nodes: %s" % nodesString)

    time.sleep(2)

    userAnswer = query_yes_no("\n\nDo you want to continue with installation on the rest of the nodes?")

    if userAnswer:
        for node in nodesList:
            system.sendline('mmdsh -N %s "rpm -Uhv %s/*.rpm"' % (node, installDirPath))
            system.prompt(timeout=20)
            print("OK : Installation completed on node: %s" % node)

    print("\nChecking currently installed packages (should be updated to a new GPFS version)")
    for node in nodesList:
        system.sendline('mmdsh -L %s "rpm -qa| grep -i gpfs"| sort' % node)
        system.prompt()
        for line in system.before.splitlines()[1:]:
            print(line)
        print("")
    else:
        sys.exit("\n## Script has been aborted by the user. ##\n")


def compileCompatibillityLayerOnAllNodes(system, nodesList):
    #TODO: needs to be tested on multiNode system
    allNodesCompilationOK = True
    nodesString = ",".join(nodesList)
    print("\nCompiling compatibility layer on the nodes (%s): " % nodesString)

    for node in nodesList:
        system.sendline('mmdsh -N %s "export SHARKCLONEROOT=/usr/lpp/mmfs/src; \
                        cd /usr/lpp/mmfs/src; make Autoconfig; make World; '
                        'make InstallImages;echo $?"' % node)
        system.prompt(timeout=30)

        exportCmdResult = system.before.splitlines()[1:]

        if exportCmdResult[-1] == "0":
            print(node + ": OK")
        else:
            print(node + ": FAIL")
            allNodesCompilationOK = False

    if not allNodesCompilationOK:
        sys.exit("\nFAIL : Compilation failed. Check /tmp/gpfs_autoinstall.log for details.\n")


def checkFilesAfterCompilationOnAllNodes(system, nodesList):
    allFilesExistOnAllNodes = True
    nodesString = ",".join(nodesList)

    print("\nChecking if the proper files have been created after compilation on all nodes (%s):" % nodesString)
    commandsToBeChecked = ["ls -l /usr/lpp/mmfs/bin/lxtrace-`uname -r`",
                           "ls -l /usr/lpp/mmfs/bin/kdump-`uname -r`",
                           "ls -l /lib/modules/`uname -r`/extra/mmfs26.ko",
                           "ls -l /lib/modules/`uname -r`/extra/mmfslinux.ko",
                           "ls -l /lib/modules/`uname -r`/extra/tracedev.ko"]

    for node in nodesList:
        for cmd in commandsToBeChecked:
            system.sendline("mmdsh -N %s " % node + cmd + '| awk \'{print $1 $6, $7, $8, $9, $10}\'; echo \"${PIPESTATUS[0]}\"')
            system.prompt()
            cmdOutput = system.before.splitlines()[2:]
            cmdResult = cmdOutput[-1]
            if cmdResult.split()[-1] == "0":
                print("OK : " + cmdOutput[0])
            else:
                print("FAIL : " + cmdOutput[0])
                allFilesExistOnAllNodes = False
        print("")

    if not allFilesExistOnAllNodes:
        sys.exit("FAIL : Can't find necessary files on some nodes. "
                 "Check /tmp/gpfs_autoinstall.log for details\n")


def rebootAllNodes(system):
    print("\nRebooting all nodes...")

    system.sendline('mmdsh "init 6"')
    system.prompt()

    print("OK : Reboot command sent to all nodes. "
          "\nPlease wait till the system is up & running again.")


def waitForServer(ipAddress):
    # TODO: this function has not been fully implemented & tested

    child = pexpect.spawn("ping -i 5 %s" % host)

    while 1:
        line = child.readline()
        if line: break
        print("Server is still down... Waiting another 10 seconds...")
        time.sleep(10)

    print("I'm UP and running again!")


if __name__ == "__main__":

    host, user, password, gpfsVersion = checkArguments()

    oneNodeSystem = True
    startTime = time.time()

    try:
        cs = pxssh.pxssh()
        cs.logfile = file(LOG_FILE_PATH, 'w')

        print("\n\nSSH-ing to ETERNUS CS (%s)..." % host)
        cs.login(host, user, password)
        gpfsTarFileName = systemPreCheck(cs, gpfsVersion)
        targetNode = getMainNodeName(cs)
        checkCurrentGPFSVersion(cs)

        print("\n============================================")
        print("GPFS version to be installed: %s" % gpfsVersion)
        print("============================================")

        userAnswer = query_yes_no("\nDo you really want to install a new GPFS?")

        if userAnswer:
            nodesList = checkIfNodesAreActive(cs)
            nodesWithoutTargetNode = [nodeName for nodeName in nodesList if nodeName != targetNode]

            if len(nodesList) != 1:
                oneNodeSystem = False

            #icpList, idpList = extractNodeTypes(nodesList)
            #disableTraces(cs)
            #saveMmlsxxOutput(cs)

            installDirPath = createInstallDir(cs, gpfsVersion)
            # installDirPath = "/tmp/GPFS.3.5.0.19"
            copyGPFSTarFile(cs, gpfsTarFileName, installDirPath, targetNode)

            if not oneNodeSystem:
                distributeGPFSTarFile(cs, targetNode, installDirPath, gpfsTarFileName, nodesList)

            unpackGPFSTar(cs, installDirPath, gpfsTarFileName)
            stoppingCSProcesses(cs)
            stoppingHSMDaemons(cs)
            unmountingInstall2000(cs)
            stoppingNfsServer(cs)
            unmountingFileSystems(cs)
            unloadKernelModules(cs)
            installGPFSOnTargetNode(cs, targetNode, installDirPath)
            compileCompatibillityLayerOnTargetNode(cs, targetNode)
            checkFilesAfterCompilationOnTargetNode(cs)

            if not oneNodeSystem:
                installGPFSOnAllNodes(cs, nodesWithoutTargetNode, installDirPath)
                compileCompatibillityLayerOnAllNodes(cs, nodesWithoutTargetNode)
                checkFilesAfterCompilationOnAllNodes(cs, nodesWithoutTargetNode)

            rebootAllNodes(cs)
            print("\n===== GPFS install procedure finished successfully =====")

            elapsedTime = time.clock() - startTime
            print("WOW! GPFS reinstallation only took: " + str(elapsedTime))
            
        else:
            sys.exit("\n## Script has been aborted by the user. ##\n")

    except pxssh.ExceptionPxssh, error:
        print("## ERROR: pxssh failed on login. ##")
        print(str(error))
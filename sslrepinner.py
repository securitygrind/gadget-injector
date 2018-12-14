#!/usr/bin/python
import os, subprocess, threading, sys, getopt
import fileinput
import random
import string
import fnmatch
from shutil import copyfile
from xml.dom import minidom
from time import sleep

def main(argv):
	try:
		opts, args = getopt.getopt(argv, "ha:c:g:r:", ["help", "target-apk=", "proxy-cert=", "frida-gadget=", "device-arch"])

		if len(opts) < 4:
			print usage()
			print "\nToo few arguments!"
			sys.exit(2)

		APK = "None"
		PROXY_CERT = "cacert.der"
		FRIDA_GADGET = "frida-gadget-12.2.26-android-x86.so"
		DEVICE_ARCH = "x86"

		for opt, arg in opts:
			if opt in ("-h", "--help"):
				print usage()
				sys.exit(2)
			elif opt in ("-a", "--target-apk"):
				APK = arg
			elif opt in ("-c", "--proxy-cert"):
				PROXY_CERT = arg
			elif opt in ("-g", "--frida-gadget"):
				FRIDA_GADGET = arg
			elif opt in ("-r", "--device-arch"):
				DEVICE_ARCH = arg

		PEM = convertDerToPem(PROXY_CERT)
		patchFridaScript(PEM)
		PACKAGE_NAME, OUTPUT_DIR, ACTIVITY_NAME = decodeApp(APK)
		tamperApp(OUTPUT_DIR, FRIDA_GADGET, ACTIVITY_NAME, APK, DEVICE_ARCH, PEM)

	except Exception as ex:
		print str(ex)
		sys.exit(2)

def convertDerToPem(cert):
	try:
		proxyCertPem = "proxy-cert.pem"
		convertToPemThread = threading.Thread(target=worker, kwargs=dict(cmd="openssl", args=["x509", "-inform", "der", "-in", cert, "-out", proxyCertPem], message="[i] Converting DER to PEM..."))
		convertToPemThread.start()
		convertToPemThread.join()
		pem = ""
		if os.path.exists(proxyCertPem):
			with open(proxyCertPem, "r+") as pemFile:
				for line in pemFile:
					pem += line
		if pem == "":
			print "[i] Incorrect certificate (use DER format)!"
			sys.exit(2)

		return pem

	except Exception as ex:
		print str(ex)
		sys.exit(2)

	finally:
		proxyCertPem = "proxy-cert.pem"
		if os.path.exists(proxyCertPem):
			os.remove(proxyCertPem)

def decodeApp(apk):
	try:
		apktoolThread = threading.Thread(target=worker, kwargs=dict(cmd="apktool", args=["d", apk, "-f"], message="[i] Decoding with apktool..."))
		apktoolThread.start()
		apktoolThread.join()

		packageName = "None"
		activityName = "None"
		outputDir = apk.split(".")[0]
		manifestPath = outputDir + "/AndroidManifest.xml"

		if os.path.isfile(manifestPath):
			xmlDoc = minidom.parse(manifestPath)
			manifestTag = xmlDoc.getElementsByTagName("manifest")

			if len(manifestTag) > 0:
				if manifestTag[0].hasAttribute("package"):
					packageName = manifestTag[0].attributes["package"].value

				activitiesTag = xmlDoc.getElementsByTagName("activity")

				if len(activitiesTag) > 0:
					for activity in activitiesTag:
						intentFilterTag = activity.getElementsByTagName("intent-filter")
						if len(intentFilterTag) > 0:
							for intent in intentFilterTag:
								actionTag = intent.getElementsByTagName("action")
								if len(actionTag) > 0:
									for action in actionTag:
										if action.hasAttribute("android:name"):
											if "MAIN" in action.attributes["android:name"].value:
												activityName = activity.attributes["android:name"].value
												break

			ymlFilePath = outputDir + "/apktool.yml"

			if os.path.isfile(ymlFilePath):
				tamperYml(ymlFilePath)

			return packageName, outputDir, activityName
		else:
			print "[i] AndroidManifest.xml not found! Aborting..."
			sys.exit(2)

	except Exception as ex:
		print str(ex)

def tamperYml(ymlFilePath):
	try:
		print "[i] Tampering yml file..."
		ymlFile = open(ymlFilePath, 'r')
		ymlFileLines = ymlFile.readlines()
		ymlFile.close()
		ymlFileUpdated = open(ymlFilePath, 'rw+')
		ymlFileUpdated.truncate(0)

		for line in ymlFileLines:
			if "versionCode:" in line:
				versionCode = line.split(":")[1].split("'")[1]
				newVersionCode = int(versionCode) + 1
				line = line.replace(versionCode, str(newVersionCode))
				ymlFileUpdated.write(line)

			else:
				ymlFileUpdated.write(line)

		ymlFileUpdated.close()
		print "[i] Done!"

	except Exception as ex:
		print str(ex)
		sys.exit(2)

def tamperApp(outputDir, fridaGadget, activityName, apk, deviceArch, pem):
	try:
		if os.path.exists(fridaGadget):
			libPath = outputDir + "/lib/" + deviceArch

			if not os.path.exists(libPath):
				os.makedirs(libPath)

			#ADD FRIDA-GADGET
			print "[+] Injecting frida-gadget..."
			copyfile(fridaGadget, libPath + "/libfrida-gadget.so")

			className = activityName.split(".")[-1]
			matches = []
			classNamePattern = '*' + className + '.smali'

			for root, dirnames, filenames in os.walk(outputDir):
				for filename in fnmatch.filter(filenames, classNamePattern):
					matches.append(os.path.join(root, filename))

			if len(matches) > 0:
				smaliFilePath = matches[0]

				if os.path.isfile(smaliFilePath):
					smaliFile = open(smaliFilePath, 'r')
					smaliFileLines = smaliFile.readlines()
					smaliFile.close()
					smaliFileUpdated = open(smaliFilePath, 'rw+')
					smaliFileUpdated.truncate(0)
					patched = False
					skipLine = False

					#INJECTS SMALI HOOK TO CALL FRIDA-GADGET LIB
					print "[+] Injecting smali hook..."
					for line in smaliFileLines:
						if ".method static constructor" in line or ".method public constructor" in line and not patched:
							smaliFileUpdated.write(line)
							nextLine = smaliFileLines[smaliFileLines.index(line)+1]
							newLocalsNumber = 1

							if ".locals" in nextLine:
								localsNumber = nextLine.split(" ")[-1]
								newLocalsNumber = int(localsNumber) + 1
								nextLine = nextLine.replace(str(localsNumber), str(newLocalsNumber))
								smaliFileUpdated.write(nextLine)
							else:
								nextLine = "    .locals " + newLocalsNumber
								smaliFileUpdated.write(nextLine)

							patched = True
							skipLine = True

							smaliFileUpdated.write('\n')
							smaliFileUpdated.write('\n')
							fridaGadgetLine = "    const-string v"+ str(newLocalsNumber-1) +", \"frida-gadget\""
							smaliFileUpdated.write(fridaGadgetLine)
							smaliFileUpdated.write('\n')
							fridaLibCallLine = "    invoke-static {v" + str(newLocalsNumber-1) + "}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V"
							smaliFileUpdated.write(fridaLibCallLine)

						elif not skipLine :
							smaliFileUpdated.write(line)

						else:
							smaliFileUpdated.write('\n')
							skipLine = False

					smaliFileUpdated.close()
				else:
					print "[-] Main activity[" + activityName + "] not found! Aborting..."
					sys.exit(2)
			else:
				print "[-] Main activity[" + activityName + "] not found! Aborting..."
				sys.exit(2)

			#BUILD TAMPERED APP
			apktoolBuildThread = threading.Thread(target=worker, kwargs=dict(cmd="apktool", args=["b", outputDir], message="[i] Re-building application"))
			apktoolBuildThread.start()
			apktoolBuildThread.join()

			#ZIPALIGN RE-BUILDED APP
			distDir = outputDir + "/dist/"
			rebuildedAppPath = distDir + apk
			if os.path.isfile(rebuildedAppPath):
				zipalignThread = threading.Thread(target=worker, kwargs=dict(cmd="zipalign", args=["-p", "4", rebuildedAppPath, distDir + outputDir + "-aligned.apk"], message="[i] Zipaligning re-builded app"))
				zipalignThread.start()
				zipalignThread.join()

			#CREATE KEYSTORE FOR SIGNING
			prngValue = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(15))
			keyStore = "keystore.pfx"
			createKeystoreThread = threading.Thread(target=worker, kwargs=dict(cmd="keytool", args=["-genkey", "-alias", "keystore", "-dname", "CN=sslunpinner, OU=SU, O=SU, L=su, S=su, C=su", "-keystore", keyStore, "-storetype", "PKCS12", "-keyalg", "RSA", "-storepass", prngValue, "-validity", "1", "-keysize", "2048"], message="[+] Creating keystore..."))
			createKeystoreThread.start()
			createKeystoreThread.join()

			#SIGN WITH APKSIGNER
			apkExt = ".apk"
			alignedAppPath = distDir + outputDir + "-aligned" 
			if os.path.isfile(alignedAppPath + apkExt):
				signThread = threading.Thread(target=worker, kwargs=dict(cmd="apksigner", args=["sign", "--ks", keyStore, "--ks-pass", "pass:" + prngValue, "--key-pass", "pass:" + prngValue, alignedAppPath + apkExt], message="[+] Signing with apksigner..."))
				signThread.start()
				signThread.join()

				signedAppPath = alignedAppPath + "-signed" + apkExt
				os.rename(alignedAppPath + apkExt, signedAppPath)
				print "[+] TAMPERED APK HERE  -> " + signedAppPath

		else:
			print "[-] Missing frida-gadged! Aborting..."
			sys.exit(2)

	except Exception as ex:
		print str(ex)

	finally:
		if os.path.isfile(keyStore):
			os.remove(keyStore)


def patchFridaScript(pem):
	try:
		fridaScriptPath = "frida-sslpinning.js"
		if os.path.exists(fridaScriptPath):
			fridaScriptFile = open(fridaScriptPath, 'r')
			fridaScriptFileLines = fridaScriptFile.readlines()
			fridaScriptFile.close()
			fridaScriptFileUpdated = open(fridaScriptPath, 'w+')
			fridaScriptFileUpdated.truncate(0)
			skipLine = False

			for line in fridaScriptFileLines:
				if skipLine:
					if "END CERTIFICATE" in line:
						fridaScriptFileUpdated.write(line)
						skipLine = False
					else:
						continue
				else:
					fridaScriptFileUpdated.write(line)

					if  "BEGIN CERTIFICATE" in line:
						certLines = pem.split("\n")
						for certLine in certLines:
							if certLine == certLines[0] or certLine == certLines[len(certLines) - 2] or certLine == "":
								continue
							else:
								fridaScriptFileUpdated.write("\t\t+ \"" + certLine + "\\n\"" + "\n")
						skipLine = True

			fridaScriptFileUpdated.close()

	except Exception as ex:
		print str(ex)

def worker(cmd, args, message):
		try:
			res = execute(cmd, args, message)
			print "Done!"

		except Exception as ex:
			print str(ex)

def execute(cmd, args, message=None):
	try:
		if message != None:
			print message

		currentCommand = [cmd]
		currentCommand.extend(args)
		#print currentCommand
		p = subprocess.Popen(currentCommand, stdout=subprocess.PIPE)
		res = p.communicate()
		return res

	except Exception as ex:
		print 'hit'
		print str(ex)

def usage():
	banner = """ ____    ____     _                           
/ ___|  / ___|   | |    
\___ \  \___ \   | |    
 ___) |  ___) |  | |___ 
|____/  |____/   |_____|
 _ __  ___  _ __   _  _ __   _ __    ___  _ __
| '__|/ _ \| '_ \ | || '_ \ | '_ \  / _ \| '__| 
| |  |  __/| |_) || || | | || | | ||  __/| |   
|_|   \___|| .__/ |_||_| |_||_| |_| \___||_|   
           |_|"""

	print banner
	print "\nUSAGE:\t"+ sys.argv[0] + " -h"
	print "\t"+ sys.argv[0] + " -a app.apk" + " -c cacert.der" + " -g frida-gadget-12.2.26-android-x86.so" + " -r x86\n" 
	print "\t-a, --target-apk\t The target apk file."
	print "\t-c, --proxy-cert\t The proxy's CA certificate file in DER format."
	print "\t-g, --frida-gadget\t The frida-gadget Android library."
	print "\t-r, --device-arch\t The device's architecture (i.e: x86)."

if __name__ == "__main__":
	main(sys.argv[1:])

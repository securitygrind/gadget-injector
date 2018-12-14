<h1>Gadget Injector</h1>

This tool automatically injects the frida-gadget binary into an Android application (provided as parameter in apk format), in order to bypass SSL Pinning to intercept and decrypt the traffic and communication between the mobile client and the server. <br />
<br />
The tool only tampers the application, installation of apk, configuration of device and running frida is expected to be done manually. 
<br />
<h2>What does it do?</h2></li>
<ol>
<li>Reverse engineer application with apktool.</li>
<li>Inject frida-gadget.</li>
<li>Inject smali hook.</li>
<li>Increase application version.</li>
<li>Re-build application with apktool.</li>
<li>Align application with zipalign.</li>
<li>Sign the application with apksigner.</li>
</ol>
<br />
<h2>Requirements</h2>
<ol>
<li>Puthon 2.7</li>
<li>apktool</li>
<li>OpenSSL</li>
<li>Frida (+ frida-gadget binary)</li>
<li>zipalign</li>
<li>Keytool</li>
<li>apksigner</li>
</ol>
<br />
To complete the task, you will also need: <br />
<ol>
<li>Android Debug Bridge (part of Android SDK) </li>
<li>Android emulation (i.e.: Genymotion). </li>
<li>Proxy (i.e.: Burpsuite). </li>
</ol>
<br />
<h2>Usage</h2>
<code>./gadget-injector.py -h </code> <br /><br />
 
		-a, --target-apk	 The target apk file.
		-c, --proxy-cert	 The proxy's CA certificate file in DER format.
		-g, --frida-gadget	 The frida-gadget Android library.
		-r, --device-arch	 The device's architecture (i.e: x86).

<br />
<code>./gadget-injector.py -a app.apk -c cacert.der -g frida-gadget-12.2.26-android-x86.so -r x86 </code><br /><br />

	[i] Converting DER to PEM...
	[i] Decoding with apktool...
	[i] Tampering yml file...
	[+] Injecting frida-gadget...
	[+] Injecting smali hook...
	[i] Re-building application
	[i] Zipaligning re-builded app
	[+] Creating keystore...
	[+] Signing with apksigner...
	[+] TAMPERED APK HERE  -> path/to/apk-aligned-signed.apk	
<br />
After that you need to: <br />
<ol>
<li>Install tampered apk on device. </li>
<li>Configure device to use proxy (i.e.: Burpsuite) </li>
<li>Run atmpered application. </li>
<li>Run <code>frida -U gadget -l frida-sslpinning.js</code> </li>
<li>Check proxy for intercepted traffic. </li>
</ol>
<br />
More on <a href="https://securitygrind.com/ssl-pinning-bypass-with-frida-gadget-sslrepinner-py" target="__blank">SSL pinning bypass with frida-gadget here</a>.
<br />
<h2>Limitations</h2>
The tool was created for and tested for a limitted amount of Android applications, tweaking the code may be necessary to make it work under specific enviroment conditions. <br />
The tool does not attempt to bypass integrity checks. <br />

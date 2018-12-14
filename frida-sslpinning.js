/* 
   Android SSL Re-pinning frida script v0.2 030417-pier 

   $ adb push burpca-cert-der.crt /data/local/tmp/cert-der.crt
   $ frida -U -f it.app.mobile -l frida-android-repinning.js --no-pause

   https://techblog.mediaservice.net/2017/07/universal-android-ssl-pinning-bypass-with-frida/
*/

setTimeout(function(){
    Java.perform(function (){
    	console.log("");
	    console.log("[.] Cert Pinning Bypass/Re-Pinning");

	    var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
	    var FileInputStream = Java.use("java.io.FileInputStream");
	    var X509Certificate = Java.use("java.security.cert.X509Certificate");
	    var KeyStore = Java.use("java.security.KeyStore");
	    var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
	    var SSLContext = Java.use("javax.net.ssl.SSLContext");
	    var String = Java.use("java.lang.String");
	    var ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
	    
	    // Load CAs from an InputStream
	    console.log("[+] Loading our CA...")
	    cf = CertificateFactory.getInstance("X.509");
	    
	    var cert = String.$new("-----BEGIN CERTIFICATE-----\n"
		+ "MIIDyTCCArGgAwIBAgIEVA06ODANBgkqhkiG9w0BAQsFADCBijEUMBIGA1UEBhML\n"
		+ "UG9ydFN3aWdnZXIxFDASBgNVBAgTC1BvcnRTd2lnZ2VyMRQwEgYDVQQHEwtQb3J0\n"
		+ "U3dpZ2dlcjEUMBIGA1UEChMLUG9ydFN3aWdnZXIxFzAVBgNVBAsTDlBvcnRTd2ln\n"
		+ "Z2VyIENBMRcwFQYDVQQDEw5Qb3J0U3dpZ2dlciBDQTAeFw0xNDA5MDgwNTEwMTZa\n"
		+ "Fw0zODA5MDgwNTEwMTZaMIGKMRQwEgYDVQQGEwtQb3J0U3dpZ2dlcjEUMBIGA1UE\n"
		+ "CBMLUG9ydFN3aWdnZXIxFDASBgNVBAcTC1BvcnRTd2lnZ2VyMRQwEgYDVQQKEwtQ\n"
		+ "b3J0U3dpZ2dlcjEXMBUGA1UECxMOUG9ydFN3aWdnZXIgQ0ExFzAVBgNVBAMTDlBv\n"
		+ "cnRTd2lnZ2VyIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgfFT\n"
		+ "KRAcski63ZXf7sL+8qsGDunoMzFvWMW4lPQKRfM4zmxZyiB2dXeTCqSuxxuHZSaV\n"
		+ "A/WaGutdtkhmWe9i3XQwHti81/Bqbec4skoyN2Cfb+up7CkNoLTS4Aypzgpn92Ji\n"
		+ "iatvuqaDHm/MkkmQA9D2CmfE6y9r3oDWIJGPTVPzrFFiZ1L/fu9FCSc1ZZjFUkr5\n"
		+ "SQjIKVEU1AoJhud5K0YPsVgfYxY7JSIPulZFw1dwWqIj7CCLcPo8mRc+Kq7B688G\n"
		+ "3n51Mv4NAqmQoDr1eJabte7JZyDoaBGCeJlAAfWEtBJgaaaeABgpOXW+/Njv2t69\n"
		+ "BobyInxlhUGD5WzMjwIDAQABozUwMzASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1Ud\n"
		+ "DgQWBBTI2LCn9s9+vyMhr+zm243BSEU0cjANBgkqhkiG9w0BAQsFAAOCAQEAXZa6\n"
		+ "9Xd6hdgzkhZj0htMw7crrdv+9z2uv6e4tXNXfs+wH+j7qcJgRlbdyDabWR0Ep2Pr\n"
		+ "7s+Y/TZc7Qn7BXpujLKI2KO735nPeoA5MkYKLEi0FYoUI1PtmtIO+b1sUwo49Rr/\n"
		+ "+mOIMzPJllsDBDIYsrYesEk/1w2J12upH1Cwr8bxDd1x74hpImuIsrRsLpIWveIq\n"
		+ "PNIIELcOrRu+NXnivmmkwUHKaSRNW2FkbysrSNcVkbhAlRWkvsgU9FHccdxGzgpt\n"
		+ "3N7Va4VU82YQiFtXDWOxI4UhxvmbyvyKQ5dNCIyeXUNuzkmhdj8AcIVuM8EzpnuL\n"
		+ "VawcRwoVdyyzqDiJqg==\n"
		+ "-----END CERTIFICATE-----");

	    var byteArrayInputStream = ByteArrayInputStream.$new(cert.getBytes());
	    var ca = cf.generateCertificate(byteArrayInputStream);
	    byteArrayInputStream.close();

	    var certInfo = Java.cast(ca, X509Certificate);
	    console.log("[o] Our CA Info: " + certInfo.getSubjectDN());

	    // Create a KeyStore containing our trusted CAs
	    console.log("[+] Creating a KeyStore for our CA...");
	    var keyStoreType = KeyStore.getDefaultType();
	    var keyStore = KeyStore.getInstance(keyStoreType);
	    keyStore.load(null, null);
	    keyStore.setCertificateEntry("ca", ca);
	    
	    // Create a TrustManager that trusts the CAs in our KeyStore
	    console.log("[+] Creating a TrustManager that trusts the CA in our KeyStore...");
	    var tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
	    var tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
	    tmf.init(keyStore);
	    console.log("[+] Our TrustManager is ready...");

	    console.log("[+] Hijacking SSLContext methods now...")
	    console.log("[-] Waiting for the app to invoke SSLContext.init()...")

	   	SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(a,b,c) {
	   		console.log("[o] App invoked javax.net.ssl.SSLContext.init...");
	   		SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").call(this, a, tmf.getTrustManagers(), c);
	   		console.log("[+] SSLContext initialized with our custom TrustManager!");
	   	}
    });
},0);

# Powershell-certificate-signing-request-and-private-key-creator

Create a private key and a certificate signing request that will be submitted to the Microsoft CA, the signed certificate and private key will then be exported to a folder. The resulting bundle consisting of private key and signed certificate can be imported to a device or endpoint that supports RSA certificates in the PEM format.
This script should not be considered production quality, it is presented here as a proof of concept. The aim was to try to build a PowerShell script that could perform some of the tasks that OpenSSL can achieve.
 
This script should be installed on a Microsoft server with the Certificate Authority (CA) service configured and running. The CA server name must be changed for your CA server in the scripts global declarations. To get the CA name execute the following command from a PowerShell prompt.
```sh
>certutil –config - -ping 
```
You will need to alter the script variable `$global:caServerName` to equal the result of the above command in this format `server FQDN/CA` the reverse of how it appears in the command result.
If the certificate templates list is empty restart this script, if problem perists restart the CA service, failing that the entire CA server will need restarting.

This script was not developed on on enterprise server so certs will only be a year in duration. It does not honour the template validity period. An enterprise CA should honour this (needs testing).
  
Because the inf file has RequestType set "PKCS10" the private key is stored in Local Comp, Certificate enrollment requests, Certifcates from the CA snapin. File location `Cert:\LocalMachine\REQUEST`.
As part of the cleanup it will be deleted from here once exported.
 
If you use an existing common name for a new key/cert it will be overwritten in the  `C:\CertsToExport` folder. You will recieve a warning.

### Screenshot

![Figure 1 - Create private key and certificate signing request screen shot](/./CertCreatorScreenShot.png "PowerShell Script form screenshot")

## Installation

Click on the link for the script above. When the PowerShell code page appears click the **Download Raw file** button top right. All the information for executing the script will be in the script synopsis.
The system this script was developed on was `Windows Server 2016`, the PowerShell version is `5.1.14393.206`.
Once installed have a read of the script in your prefered editor. Find each line that has the comment text `CHANGEME` in it. Alter these lines to match your enviroment.
## Usage

To execute the PowerShell scripts in this repository. Save the ps1 file to a folder on your computer, then from a powershell prompt in the same folder.
```sh
Run .\CertCreator.ps1 
```

If your Windows enviroment permits, you could create a shortcut to the script. Paste the following line into the shortcut.
```sh
powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\<PathToYourScripts>\CertCreator.ps1"
```
Then just double click the shortcut like you are starting an application. Check the correct path to the  PowerShell executable on your system. Depending on your system you may have to right click the script shortcut and `Run as administrator` (needs testing).

## Known Problems
This script encrypts the private key using the PBKDF1 standard. This standard is practically obselete, but still supported at the time this script was authored. To try and mitigate the risks the script applys a high entrophy pass phrase.

## Credits and references

#### [Extract PEM from SSL certificate](https://stackoverflow.com/questions/52492644/azure-powershell-extract-pem-from-ssl-certificate)
The basis for this script comes from this StackOverflow post. Thanks to user RashadRivera.
#### [Trying to create an encypted private key in PowerShell the same way Openssl does it](https://stackoverflow.com/questions/72127462/trying-to-create-an-encypted-private-key-in-powershell-the-same-way-openssl-does)
Another Stackoverflow post. Thanks to user Tapaco, who's answer solves most of the problems I had with this script.
#### [PEM private key](https://www.openssl.org/docs/man1.1.1/man3/PEM_write_RSAPrivateKey.html)
Open SSL documentation for private key encryption. Scroll down to the PEM ENCRYPTION FORMAT section.

Check the comments within the script for more credits.

----

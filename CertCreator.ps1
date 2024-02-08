<#
.SYNOPSIS
  Name: CertCreator.ps1
  Create a private key and a certificate
  signing request that will be submitted
  to the CA and exported.
 
.DESCRIPTION
  CA server name must be changed for your CA server in
  the global declarations. This script should be executed on the CA server.

  If the templates list is empty restart this app, if problem perists
  restart the CA service, failing that the entire CA server will need restarting.

  This script was not developed on on enterprise server so certs will
  only be a year in duration. It does not honour the template validity period.
  An enterprise CA should honour this. Needs testing
  Because the inf file has RequestType set "PKCS10" the private key
  is stored in Local Comp, Certificate enrollment requests, Certifcates from the snapin.
  File location Cert:\LocalMachine\REQUEST
  As part of the cleanup it will be deleted from here once exported.
 
  If you use an existing common name for a new key/cert it will be overwritten in the
  C:\CertsToExport folder. You will recieve a warning.
 
.NOTES
Copyright (C) 2022  A Cripps
 
 
     This program is free software: you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published by
     the Free Software Foundation, version 3.
 
     This program is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
     GNU General Public License for more details.
 
     To view the GNU General Public License, see <http://www.gnu.org/licenses/>.

    Release Date: 03/02/2022
    Last Updated:        
   
    Change comments:
    Initial realease - AC
   
   
  Author: Crippa AC
       
.EXAMPLE
  Run .\CertCreator.ps1 <no arguments needed>
  Or create shortcut to:
  "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\<PathToYourScripts>\CertCreator.ps1"
  Then just double click the shortcut like you are starting an application. Or better still
  right click and run as administrator.

#>

#----------------[ Declarations ]-----------------------------------------------------#

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"                                     # What to do if an unrecovable error occures
$global:scriptPath = Split-Path -Path $MyInvocation.MyCommand.Path  # This scripts path
$global:scriptName = $MyInvocation.MyCommand.Name                   # This scripts name
$global:workingFolder = "C:\CertsToExport"                          # Folder where certs/keys saved
$global:subject = "OU=MYUNIT,O=MYORG,C=GB"                          # Default subject names for the certifivate CHANGEME
$global:caServerName = "WIN1DS.voicevid.co.uk\voicevid-WIN1DS-CA"   # My CA, find using certutil –config - -ping CHANGEME
$wpf = @{ }                                                         # A hash table to store node names from the XAML below
                                                                    # hash tables are key/value stored arrays, each
                                                                    # value in the array has a key

Add-Type -AssemblyName presentationframework, presentationcore      # Add these assemblys

# Information files. Details used by certreq
# to create the certificate. Will not be read untill
# $aVar = $ExecutionContext.InvokeCommand.ExpandString($global:settingsInf) invoked
$global:settingsInf = @'
[NewRequest]
KeyLength =  2048
Exportable = TRUE
MachineKeySet = TRUE
SMIME = FALSE
RequestType = PKCS10
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType =  12
HashAlgorithm = sha256
Subject = "$($subjectNames + ",CN=" + $deviceCommonName)"
[RequestAttributes]
CertificateTemplate = "$certTemplate"
'@

# Text help file that will be writen out to the
# working folder. Will not be read untill
# $aVar = $ExecutionContext.InvokeCommand.ExpandString($global:textFile) invoked                                                                
$global:textFile = @'
*************************************************************
 Once you have imported the cert and private key onto the  
 target device, delete the folder:
 $newWorkingFolder
 Then delete the same folder from the Recycle bin to
 completely remove it from this computer.
*************************************************************
Explanation of the files in this folder, plus what to do next

$commonName.pfx
-------------------
A PKCS#12 key store containing the private key and unsigned
public certificate. This file is not used by the Cisco endpoints.
Access to this file requires the following password.
$keyPasWd

$commonName.cer
-------------------
Signed public certificate to import onto the endpoint. The endpoint will
accept cer files even though it specifies pem files.

$("$commonName" + "PRIVEnc.pem")
-----------------------
The encrypted private RSA key encoded as a base 64. This file will
only be present if you ticked password Y or N.
If this file is present the password will be
$keyPasWd

$("$commonName" + "PRIV.pem")
---------------------------
The private RSA key encoded as a base 64. This file will
only be present if you did not tick password Y or N.
No password is needed for this file.

How to import cert/private key to a Cisco Telepresense endpoint e.g.DX80
------------------------------------------------------------------------
Browse to the endpoint. Log in.
Navigate to Security->Certificates

In the Add Certificate group box click the browse
button next to Certificate.
Navigate to the folder containing the files above.
Select the $commonName.cer file, click open.

Now click the browse button next to Private Key (optional)
Navigate to the folder containing the files above.
Select the $("$commonName" + "PRIV.pem") file, click open.

Now click Upload. Both the cert and private key must be uploaded
together, as a pair!!
'@

#----------------[ End Of Declarations ]----------------------------------------------#

######################################################################################
#       Here-String with the eXAppMarkupLang (XAML) needed to display the GUI        #
######################################################################################

# A here-string of type xml
[xml]$xaml=@"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        ResizeMode="CanResizeWithGrip" Name="certCreatorGui"
        Title="PKI RSA Private Key and Cert creator V1" Height="800" Width="700"
        Background="#FFFFFFFF" FontSize="15" FontFamily="Segoe UI">

    <Window.Resources> <!--Match name with the root element in this case Window-->
        <!--Setting default styling for all buttons-->  
        <Style TargetType="Button">
         <Setter Property="Width" Value="143" />
         <Setter Property="Height" Value="32" />
         <Setter Property="Margin" Value="10" />
         <Setter Property="FontSize" Value="18" />
         <Setter Property="Background" Value="#FFB8B8B8" />
        </Style>
        <Style TargetType="TextBox">
         <Setter Property="Background" Value="#FFB8B8B8" />
         <Setter Property="Height" Value="32" />
        </Style>
        <Style TargetType="ComboBox">
         <Setter Property="Background" Value="#FFB8B8B8" />
         <Setter Property="Height" Value="32" />
        </Style>
     </Window.Resources>

    <Grid Name="MainGrid">
     
      <Grid.RowDefinitions>
        <RowDefinition Name ="Row0" Height="90*"/><!--Row 0 Row Heights as percentage of entire window-->
        <RowDefinition Name="Row1" Height="0*"/> <!--Row 1-->
        <RowDefinition Name="Row2" Height="0*"/> <!--Row 2-->
        <RowDefinition Name="Row3" Height="10*"/> <!--Row 3-->
      </Grid.RowDefinitions>
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>           <!--Column 0-->
      </Grid.ColumnDefinitions>

       <DockPanel>
        <Menu DockPanel.Dock="Top" Background="#FFFFFFFF">
            <MenuItem Header="_File">
                <MenuItem Header="_About" Name="menuItemAbout"/>
                <Separator />
                <MenuItem Header="_Exit" Name="menuItemExit"/>
            </MenuItem>
        </Menu>
       </DockPanel>
       
        <GroupBox Name="instructionsGrpBox" Grid.Row="0" Grid.Column="0" Header="Instructions" Visibility="Visible" BorderThickness="0.5" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Margin="15">
                <TextBlock Name="instructionsTxtBlk" TextWrapping="Wrap" VerticalAlignment="Top"
                Text = "&#x0a;
                This script will create a Private key and submit the coresponding&#x0a;
                Certificate Signing Request to the CA.&#x0a;&#x0a;
                The resulting Private key and signed certificate can be&#x0a;
                imported into a device that supports PEM files.&#x0a;
                To take a look at the defaults, open this script in Notepad&#x0a;
                or Powershell ISE&#x0a;
                If the certificate template drop down list is empty&#x0a;
                check your server has the CA service activated.&#x0a;&#x0a;
                Press OK to continue. Press Cancel to quit.&#x0a;                
                "/>
        </GroupBox> <!---->

        <GroupBox Name="UserInputGrpBox" Grid.Row="0" Grid.Column="0" Header="Please complete the following" Visibility="Hidden" BorderThickness="0.5" HorizontalAlignment="Stretch" Margin="15" VerticalAlignment="Top" >
           <StackPanel>
            <TextBlock Padding="10">Name of certificate template:</TextBlock>
            <ComboBox Name="CertTemplateComboBox"  HorizontalAlignment="Stretch">
                <!--Combo box populated with the output of command certutil-adtemplate-->
            </ComboBox>
            <TextBlock Padding="10">Common Name (CN):</TextBlock>
            <TextBox Name="commonNameTxtBox" />
            <TextBlock Padding="10">Subject Names. Comma separated (OU,O,C):</TextBlock>
            <TextBox Name="subjectNamesTxtBox" />
            <TextBlock Padding="10">Subject Alternative Names. Comma separated (SAN1,SAN2):</TextBlock>
            <CheckBox Name="sanChkBox" Margin="410,-26,0,0" IsChecked="False" />
            <TextBox Name="sanNamesTxtBox" IsEnabled="false" />
           </StackPanel>
        </GroupBox>

        <GroupBox Name="passwordGrpBox" Grid.Row="1" Grid.Column="0" Header="Password to access the Private Key" Visibility="Hidden" BorderThickness="0.5" HorizontalAlignment="Stretch" Margin="15"  VerticalAlignment="Top">
            <Grid Name="passwordGrid">
             <StackPanel>
              <TextBlock Padding="10">If you do not want to password protect the Private Key, untick the box below.</TextBlock>
              <CheckBox Name="passwordChkBox"  Content = "Password Y or N" HorizontalAlignment="Left"  Margin="10,10,0,0" IsChecked="False" />
              <TextBlock Padding="10">password:</TextBlock>
              <TextBox Name="passwordTxtBox" IsReadOnly="True" />
             </StackPanel>
            </Grid>
        </GroupBox>

        <GroupBox Name="resultsGrpBox" Grid.Row="2" Grid.Column="0" Header="Console Messages" Visibility="Hidden" BorderThickness="0.5" HorizontalAlignment="Stretch" Margin="10,0,10,10"  VerticalAlignment="Stretch" >
            <Grid Name="resultsGrid">
             <ScrollViewer>
                <TextBlock Name="Output_TxtBlk" TextWrapping="Wrap" TextAlignment="Left" VerticalAlignment="Stretch" />
             </ScrollViewer>
            </Grid>
            <!---->
        </GroupBox>

        <StackPanel Name="OkCancelStackPanel" Grid.Row="3" Grid.Column="0" HorizontalAlignment="Right" Orientation="Horizontal" >
            <Button Name="oKButton1" Content="OK"  />
            <Button Name="oKButton2" Visibility="Collapsed" Content="OK"  />
            <Button Name="myCancelButton" Content="Cancel" />
        </StackPanel>

    </Grid>
</Window>
"@

#------------------[ Functions ]------------------------------------------------------#
#######################################################################################
#        Function to exit the script, called by the cancel buttons                    #
#######################################################################################

function Close-AndExit
{
    $wpf.certCreatorGui.Close()    
}

#######################################################################################
#        Function that generates a 16 char password                                   #
#######################################################################################

function Get-RandomPassword {
    [int] $length      = 16  # Number of characters in the password
    [int] $charPolicy  = 2   # Amount of upper, lower case, numbers and special characters

    # Character set to choose from
    # Numbers are from the ASCII table, omited special characters that Cisco objects to

    $charSet = [char[]] (  48..57 `
                         + 65..90 `
                         + 97..122 `
                         + ("/","*","-","+","!","?","=","(",")","[","]","@",":","_")
                        )


    # Generate a new password until it meets the specified policy
    do {
        $password = -join ($charSet | Get-Random -Count $length)
        $uppercase = ($password.ToCharArray() -cmatch "[A-Z]").Count
        $lowercase = ($password.ToCharArray() -cmatch "[a-z]").Count
        $numbers =   ($password.ToCharArray() -match "[0-9]").Count
        $special =   ($password.ToCharArray() -match "[^a-zA-Z0-9]").Count
    } while ($uppercase -lt $charPolicy -or $lowercase -lt $charPolicy -or $numbers -lt $charPolicy -or $special -lt $charPolicy)

    $password
}

#######################################################################################
#      Function to check that the user has either entered some text in the txt        #
#                 boxes or seleced from the drop down lists                           #
#######################################################################################

function Check-UserInput
{
    $resultBool = $true

    # Checking for valid user input
    if ( ([string]::IsNullOrEmpty($wpf.commonNameTxtBox.Text)) -or
         ([string]::IsNullOrEmpty($wpf.CertTemplateComboBox.Text)) -or
         ([string]::IsNullOrEmpty($wpf.subjectNamesTxtBox.Text)))
    {
        $resultBool = $false
        $wpf.Output_TxtBlk.Foreground = "Red"
        $wpf.Output_TxtBlk.Text = "One of the following is missing`nA template from the drop down list`nA Common Name`nSubject Names`n"
    }

    if ($wpf.sanChkBox.IsChecked)
    {
        if ( ([string]::IsNullOrEmpty($wpf.sanNamesTxtBox.Text)) )
        {
            $resultBool = $false
            $wpf.Output_TxtBlk.Foreground = "Red"
            $wpf.Output_TxtBlk.Text = "You have checked the SAN check box but not given any names!`n"
        }
    }

    $resultBool
}

#######################################################################################
#      If it dosn't already exist create a working directory to store keys and        #
#                                   certs                                             #
#######################################################################################

function Create-WorkingDir
{
    if (Test-Path -Path $global:workingFolder) {
        return
    } else {
        new-item $global:workingFolder -itemtype directory
    }
}

#######################################################################################
#      Create a new key pair and a public cert. Export a CSR for the public cert      #
#      to a new keyCertFolder. Private key is in Local Comp, Personal, Certifcates    #
#######################################################################################

function Create-PrivKeyAndCsr ($deviceCommonName, $certTemplate, $subjectNames)
{
    # Filename for this cert with all special characters removed
    $fileName = $($deviceCommonName -replace "[\W]", "").Trim()
   
    # Expand the settings inf var to include the
    # variables above $deviceCommonName, $certTemplate
    # so please dont remove them!!
    $settingsInf = $ExecutionContext.InvokeCommand.ExpandString($global:settingsInf)

    # If Subject Alternative Names ticked add these to the $settingsInf
    if ($wpf.sanChkBox.IsChecked)
    {
        $sanNames = $wpf.sanNamesTxtBox.Text
        $sanNames = $sanNames.Replace(",", "&dns=") # Replace the commas for &dns=

        # OID extension for Subject Alt Names
        # DNS FQDNs string must be enclosed in double quotes
        $sanNames =     "`r`n[Extensions]`r`n" `
                      + "2.5.29.17 = `"{text}dns=$sanNames`""
        $settingsInf = $settingsInf + $sanNames
    }

    # Create a working folder just for this key/cert. Overwrite if its already there
    $keyCertFolder = $global:workingFolder + "\" + $fileName
    New-Item $keyCertFolder -itemtype directory -Force | Out-Null

    # Write the inf settings out to a file, overwrite
    $settingsInf | Out-File $($keyCertFolder + "\certSettings.inf") -Force

    Try {
            # Need to be careful here. certreq & certutil are executables they can
            # take a long time to complete. The script will move on rather than wait. Piping to null
            # or out-string forces a wait
            certreq -new $($keyCertFolder + "\certSettings.inf") $($keyCertFolder + "\" + $fileName + ".csr") | Out-Null

            # If a success display message to the console
            $wpf.Output_TxtBlk.Text += "New private key and CSR created.. "

            # Refresh the GUI otherwise it waits for the functions to complete
            $wpf.certCreatorGui.Dispatcher.Invoke([action]{},"Render")
        }
    Catch {            
            $wpf.oKButton2.IsEnabled = $true # Turn the OK button on
            # Display any error message to the console
            $wpf.Output_TxtBlk.Foreground = "Red"
            $wpf.Output_TxtBlk.Text += “`nan error occurred`n $_`n`n”
            # break # Consider putting break to stop the script on failure
        }
    $keyCertFolder
}

#######################################################################################
#   Submit the CSR, retrive the signed cert as a cer file and the private key         #
#                        wrapped up in a pfx file                                     #
#######################################################################################

function Submit-CertCsr ($newWorkingFolder, $commonName, $certTemplate)
{
    # Filename for this cert and pfx with all special characters removed
    $fileName = $($commonName -replace "[\W]", "").Trim()
   
    Try {
            # Need to be careful here. certreq & certutil are executables they can
            # take a long time to complete. The script will move on rather than wait. Piping to null
            # or out-string forces a wait
            # Reminder: ` splits a long line
            $results = certreq `
                       -f `
                       -config $global:caServerName `
                       –attrib “CertificateTemplate:$certTemplate” `
                       –submit "$newWorkingFolder\$fileName.csr" "$newWorkingFolder\$fileName.cer" | Out-String

            # If this is executing on enterprise CA the submit above may issue
            # automatically, making the resubmit/retrieve redundant. If not do a resubmit/retrieve
            if($results -like "*Taken Under Submission*") {
                $requestIdForCert = $($results | Select-String 'RequestId: (\d+)').Matches[0].Groups[1].Value.Trim() # get the request id
                certutil -resubmit $requestIdForCert | Out-Null
                certreq -f -config $global:caServerName -retrieve $requestIdForCert "$newWorkingFolder\$fileName.cer" | Out-Null
            }
           

            # If a success display message to the console
            $wpf.Output_TxtBlk.Text += "CSR submitted`nCER and PFX file retrieved.. "

            # Refresh the GUI otherwise it waits for the functions to complete
            $wpf.certCreatorGui.Dispatcher.Invoke([action]{},"Render")
        }
    Catch {            
            $wpf.oKButton2.IsEnabled = $true # Turn the OK button on
            # Display any error message to the console
            $wpf.Output_TxtBlk.Foreground = "Red"
            $wpf.Output_TxtBlk.Text += “`nan error occurred`n $_`n`n”
            # break # Consider putting break to stop the script on failure
        }
     
}

#######################################################################################
#              Convert the signed cert and private key to pem format                  #
#                                                                                     #
#######################################################################################

function Convert-KeyAndCert ($newWorkingFolder, $commonName, $privKeyPasWd)
{
    # Filename for this cert and pfx with all special characters removed
    $fileName = $($commonName -replace "[\W]", "").Trim()

    # The thumprint of the cert that has the private key
    $certDetails = Get-ChildItem -Path Cert:\LocalMachine\REQUEST  | where {$_.Subject –like "*$fileName*"}
    $certThumbprint = $certDetails.Thumbprint

    # Export entire cert and private key as a pfx file to the working folder
    # Reminder the ` character splits a long line
    Get-ChildItem `
        -Path ("Cert:\LocalMachine\REQUEST\" + $certThumbprint) | `
        Export-PfxCertificate `
            -FilePath $newWorkingFolder\$fileName.pfx `
            -Password $privKeyPasWd `
            -ChainOption EndEntityCertOnly `
            -NoProperties | Out-Null

    Try {
            # Convert the privatekey to pem format calls function Export-PrivateKeyPem
            # Need to be careful here. certutil is an executable it can
            # take a long time to complete. The script will move on rather than wait. Piping to null
            # or out-string forces a wait.
            $pfxExportOptions = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
            $pfxAsCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("$newWorkingFolder\$fileName.pfx", $privKeyPasWd, $pfxExportOptions)
           

            # Call the Export-PrivateKeyPem or Export-PrivateKeyPemEncrypted
            # function depending upon if a password was specified. Check for presence of
            # text in the password field
            # Both use dotNet to convert private key to pem format
            if ([System.String]::IsNullOrEmpty($wpf.passwordTxtBox.Text)){
                $privateKeyName = "$newWorkingFolder\$fileName" + "PRIV.pem"
                Export-PrivateKeyPem $pfxAsCertificate $privateKeyName
            }
            else {
                $privateKeyName = "$newWorkingFolder\$fileName" + "PRIVEnc.pem"
                Export-PrivateKeyPemEncrypted $pfxAsCertificate $privateKeyName
            }
           
            # Convert the signed cert cer file to pem NOT NEEDED, JUST UPLOAD THE cer FILE
            #$certName = "$newWorkingFolder\$fileName" + "CERT.pem"
            #certutil -encode "$newWorkingFolder\$fileName.cer" $certName | Out-Null
           

            # If a success display message to the console
            $wpf.Output_TxtBlk.Text += "Private Key encoded to pem format`n" + `
                                       "See folder $newWorkingFolder`n"+ `
                                       "Details are in the README.txt file"

            # Refresh the GUI otherwise it waits for the functions to complete
            $wpf.certCreatorGui.Dispatcher.Invoke([action]{},"Render")
        }
    Catch {            
            $wpf.oKButton2.IsEnabled = $true # Turn the OK button on
            # Display any error message to the console
            $wpf.Output_TxtBlk.Foreground = "Red"
            $wpf.Output_TxtBlk.Text += “`nan error occurred`n $_`n`n”
            # break # Consider putting break to stop the script on failure
        }

    $certThumbprint
     
}

#######################################################################################
#              Function to extract the private key from the pfx file                  #
#                !!!Exports as a plain language PEM file!!!                           #
#######################################################################################

function Export-PrivateKeyPem([System.Security.Cryptography.X509Certificates.X509Certificate2]$pfx, [System.String]$outputPath) {
   
    # Will only process RSA keys NOT eliptic curve. See certSettings.inf file, provider name, for details
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($pfx)
    $rsaCng = ([System.Security.Cryptography.RSACng]$rsa)
    $key = $rsaCng.Key
   
    # The following is quite odd. Despite using Pkcs8PrivateBlob (binary large object)
    # to export the key, openssl asn1parse shows it as PKCS1
    # rsaEncryption as per RFC5208 Page 3
    $base64CertText = [System.Convert]::ToBase64String($key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob), "InsertLineBreaks")

    $out = New-Object String[] -ArgumentList 3

    # PEM file encoded to the PKCS1 standard key
    # type,RSA must be included in the header/footer
    # despite PKCS8 blob above??
    # If it was PKCS8 header would be
    # -----BEGIN PRIVATE KEY-----
    $out[0] = "-----BEGIN RSA PRIVATE KEY-----"
    $out[1] = $base64CertText
    $out[2] = "-----END RSA PRIVATE KEY-----"

    $out | Out-File $outputPath
    # this remove CR/LF combination that openssl hates
    (Get-Content $outputPath) | Set-Content $outputPath
}

#######################################################################################
#              Function to extract the private key from the pfx file                  #
#  See https://www.openssl.org/docs/man1.1.1/man3/PEM_write_RSAPrivateKey.html        #
#  section labeled PEM ENCRYPTION FORMAT for explanation of how this is done          #
#                           the openssl way                                           #
#                   !!!Exports as an encrypted PEM file!!!                            #
#######################################################################################

function Export-PrivateKeyPemEncrypted([System.Security.Cryptography.X509Certificates.X509Certificate2]$pfx, [System.String]$outputPath) {

    # Will only process RSA keys NOT eliptic curve. See certSettings.inf file, provider name, for details
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($pfx)
    $rsaCng = ([System.Security.Cryptography.RSACng]$rsa)
    # Export key in PKCS#1 format
    # blob is binary large object
    #$dataToEncrypt = $rsaCng.ExportRSAPrivateKey() # Posh V7 only sadly
    $keyToEncryptThumbPrint = $rsaCng.Key
    # Read comments in Export-PrivateKeyPem function about Pkcs8PrivateBlob
    $dataToEncrypt = $keyToEncryptThumbPrint.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
   
    # Convert the password into a byte array
    # Get the password from the form
    $passphrase = $wpf.passwordTxtBox.Text
    [byte[]] $passwordBytes = [Text.Encoding]::UTF8.GetBytes($passphrase) # 16 bytes
   
    # Create 16 byte random IV
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()  
    $IV = New-Object System.Byte[](16)
    $rng.GetBytes($IV)

    # Get 8 byte salt
    $saltBytes = $IV[0..7]

    # Create a new instance of the MD5 hashing algorythum
    $md5 = New-Object System.Security.Cryptography.MD5CryptoServiceProvider
   
    # Pre openssl V1.1.0 way to create an encryption key
    # from a password. This is a bit like the
    # obelete standard
    # RFC2898 PBKDF1, but not exactly.
    # Google EVP_BytesToKey
    [byte[]]$firstIteration = $md5.ComputeHash($passwordBytes + $saltBytes) # 16 bytes
    [byte[]]$secondIteration = $md5.ComputeHash($firstIteration + $passwordBytes + $saltBytes) # 16 bytes
   
    # Derive the encryption key and Initialization vector
    [byte[]]$key = $firstIteration + $secondIteration

    # Geneate an AES symetrical encryption standard object
    # This is the encryption algorythum that will encrypt
    # our private key using the key derived from the password above
    $aesManaged = New-Object System.Security.Cryptography.AesManaged
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256

    # Instruct AES object what the key and IV are
    $aesManaged.Key = $key
    $aesManaged.IV = $IV
    $ivAsString = [System.BitConverter]::ToString($IV) -replace "-"
    #Write-Host " iv  = $ivAsString"
    #Write-Host " key = $([System.BitConverter]::ToString($aesManaged.Key) -replace "-")"

    # Now do the actual encypting of the RSA private key
    # Data to encrypt must be binary formatted into an array
    # of bytes
    $encryptor = $aesManaged.CreateEncryptor()
    [byte[]] $encryptedData = $encryptor.TransformFinalBlock($dataToEncrypt, 0, $dataToEncrypt.Length)
    $aesManaged.Dispose()

    # Format the base64 string into lines of 64
    # which is what openssl does
    $base64CertText = [System.Convert]::ToBase64String($encryptedData) -replace ".{64}", "`$&`r`n"
   
    # Creat a variable to store the encypted key
    $out = New-Object String[] -ArgumentList 5

    # PEM file. See RFC1421 page 24
    # for heading explanations
    # This is an encrypted PKCS1 private key
    # so you cannot access ASN1 data about the key
    # hence the heading info
    # despite PKCS8 blob above the exported
    # key is formatted PKCS1??.A PKCS8 encrypted
    # private key would have header
    # -----BEGIN ENCRYPTED PRIVATE KEY-----
    $out[0] = "-----BEGIN RSA PRIVATE KEY-----"
    $out[1] = "Proc-Type: 4,ENCRYPTED"
    $out[2] = "DEK-Info: AES-256-CBC,$ivAsString`r`n"
    $out[3] = $base64CertText
    $out[4] = "-----END RSA PRIVATE KEY-----"
   
    $out | Out-File $outputPath
    # this removes CR/LF combination that openssl hates
    (Get-Content $outputPath) | Set-Content $outputPath
}

#----------------[ Main Execution ]---------------------------------------------------#

#######################################################################################
#               Read the XAML needed for the GUI                                      #
#######################################################################################

$reader = New-Object System.Xml.XmlNodeReader $xaml
$myGuiForm=[Windows.Markup.XamlReader]::Load($reader)

# Collect the Node names of buttons, txt boxes etc.

$namedNodes = $xaml.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]")
$namedNodes | ForEach-Object {$wpf.Add($_.Name, $myGuiForm.FindName($_.Name))}

# Populate the Cert template drop down list
# if the list is empty make sure you have installed on a
# CA sevrer

$certTemplateList = certutil -adtemplate
$templateComboBox = $myGuiForm.FindName("CertTemplateComboBox")
foreach ($certTemplate in $certTemplateList)
{
    $templateComboBox.Items.Add($certTemplate.split(':')[0]) | Out-Null #  no output to the console please
}

#######################################################################################
#               This code runs when endpoint credentials radio button is checked      #
#######################################################################################

$wpf.passwordChkBox.Add_Checked({
     $wpf.passwordTxtBox.Text = Get-RandomPassword
})

#######################################################################################
#               This code runs when endpoint credentials radio button is unchecked    #
#######################################################################################

$wpf.passwordChkBox.Add_UnChecked({
     $wpf.passwordTxtBox.Text = $null
})

#######################################################################################
#           This code runs when subject alternative name radio button is checked      #
#######################################################################################

$wpf.sanChkBox.Add_Checked({
     $wpf.sanNamesTxtBox.IsEnabled = $true # Enable the SAN textbox for editing
})

#######################################################################################
#           This code runs when subject alternative name radio button is unchecked    #
#######################################################################################

$wpf.sanChkBox.Add_UnChecked({
     $wpf.sanNamesTxtBox.IsEnabled = $false # Grey out the SAN textbox
     $wpf.sanNamesTxtBox.Text      = ""     # Clear the text box of any text
})

#######################################################################################
#               This code runs when the Menu Item about button is clicked             #
#######################################################################################

$wpf.menuItemAbout.Add_Click({
     #Show the help synopsis in a GUI
     Get-Help "$global:scriptPath\$global:scriptName" -ShowWindow
})

#######################################################################################
#               This code runs when the Menu Item exit button is clicked              #
#######################################################################################

$wpf.menuItemExit.Add_Click({
     #Call the close and exit function
     Close-AndExit
})

#######################################################################################
#               This code runs when the Cancel buttons are clicked                    #
#######################################################################################

$wpf.myCancelButton.Add_Click({
     #Call the close and exit function
     Close-AndExit
})

#######################################################################################
#               This code runs when the OK 1 button is clicked                        #
#######################################################################################

$wpf.oKButton1.Add_Click({
   
    $wpf.instructionsGrpBox.Visibility = "Hidden"
    $wpf.oKButton1.Visibility = "Hidden"
    $wpf.Row0.Height = "45*"
    $wpf.Row1.Height = "30*"
    $wpf.Row2.Height = "15*"
   
    $wpf.UserInputGrpBox.Visibility = "Visible"
    $wpf.passwordGrpBox.Visibility = "Visible"
    $wpf.resultsGrpBox.Visibility = "Visible"
    $wpf.oKButton2.Visibility = "Visible"
   
})

#######################################################################################
#               This code runs when the OK 2 button is clicked                        #
#######################################################################################

$wpf.oKButton2.Add_Click({
   
    # Call the user input check
    if ( Check-UserInput )
    {
        $certTemplate = $wpf.CertTemplateComboBox.Text
        $commonName   = $wpf.commonNameTxtBox.Text
        $subjectNames = $wpf.subjectNamesTxtBox.Text
        $keyPasWd     = $wpf.passwordTxtBox.Text

        # Check if a password was selected. If not set password will
        # be used for access to the PFX file but not PEM file
        if (-Not([System.String]::IsNullOrEmpty($keyPasWd))) {
            # Password requested. Both PFX and PEM private
            # keys use the displayed password.
            # ConvertTo-SecureString is a secure way of storing a password
            $privKeyPasWd = ConvertTo-SecureString -String $keyPasWd -Force -AsPlainText
        }
        else {
            # Password not requested. Only PFX private
            # keys use a password.
            $keyPasWd = Get-RandomPassword
            $privKeyPasWd = ConvertTo-SecureString -String $keyPasWd -Force -AsPlainText
        }
       
        $msgText      = "Do you want to create a key pair using template $certTemplate`nand common name $commonName`n"
        $messageResp  =
        [System.Windows.MessageBox]::Show(
        $msgText,
        'Cert Creator',
        'OkCancel'
        )
        if ( $messageResp -eq 'OK' )
        {
             $wpf.oKButton2.IsEnabled = $false # Turn the OK button to greyed out
             $wpf.Output_TxtBlk.Foreground = "Black"
             $wpf.Output_TxtBlk.Text = "Creating Key Pair. Please wait...`n"

             # Refresh the GUI otherwise it waits for the functions to complete
             $wpf.certCreatorGui.Dispatcher.Invoke([action]{},"Render")
             
             # Start the priv key/cert creation
             Create-WorkingDir
             $newWorkingFolder = Create-PrivKeyAndCsr $commonName $certTemplate $subjectNames

             # Submit the CSR to the CA
             Submit-CertCsr $newWorkingFolder $commonName $certTemplate

             # Convert private key to pem format
             $certThumbPrint = Convert-KeyAndCert $newWorkingFolder $commonName $privKeyPasWd

             # Permanently remove disued files and the key/cert from local computer keystore
             Remove-Item "$newWorkingFolder\*.csr", "$newWorkingFolder\*.inf", "$newWorkingFolder\*.rsp"
             Remove-Item "Cert:\LocalMachine\REQUEST\$certThumbPrint"

             # Output a text help file to the working folder
             # first expand the var
             $commonName = $($commonName -replace "[\W]", "").Trim()
             $textOutput = $ExecutionContext.InvokeCommand.ExpandString($global:textFile)
             $textOutput | Out-File -FilePath "$newWorkingFolder\README.txt" -Force

             # Turn the OK button back on
             $wpf.oKButton2.IsEnabled = $true
        }
    }

  })
 
#######################################################################################
#               Show the GUI window by name                                           #
#######################################################################################

$wpf.passwordChkBox.IsChecked = $true       # Force a password for private key
$wpf.subjectNamesTxtBox.Text = $global:subject  # Default Subject names, can be overwitten by user
$wpf.certCreatorGui.ShowDialog() | out-null # null dosn't show false on exit
# Sync-CACerts
Use a Group Managed Serice Account (gMSA) with a scheduled task to create on-premise Active Directory placeholder computer objects for Entra-Joined devices containing the serial numbers of recently issued certificates. Sync-CACerts was created in response to the [KB5014754][2] changes that would enforce strong certifiate binding. I was/am using 802.1x port level authentication, WAP2/3-Enterprise with device certificates, and Microsoft's AlwaysOn VPN with both computer and user certificates. All certificate authentication uses the MS Network Policy Service (NPS), which is MS RAIDUS vairent. When NPS checked AD as part of authentication, the strong cert binding changes would require NPS to find strong binding between the AD object (user or computer) and the certificate.

The certificates are issued by our Private Key Infrastructure (PKI). Our PKI start with a Enterprise Certificate Root Authory using Active Directroy Certificate Service. Intune certificate connectors for PKCS and SCEP certificates. The SCEP certificate runs on a Network Device Enrollment Service (NDES). I do not recommned the NDES server.

Sync-CACerts does the following:
+ Get all the issues certificates matching a tempalte OID
+ Get managed devices from Intune that match a filter (only Entra-Joined)
+ For each of the last 5 issued certs for an Issued Common Name that matches an Intune managed device
  + Find or add the computer object
  + Add the serial number of the certificate to the AD Comptuer's altSecurityIdentities attribute
# Requirements
+ Active Directory
+ Active Directory Certificate Services
+ Microsoft Graph
  + with PowerShell module
+ Entra ID App Registration
  + with matching local certificate
+ [BladeFireLight's Get-IssuedCertificate function][1]

  [1]: https://www.powershellgallery.com/packages/PKITools/1.6/Content/Get-IssuedCertificates.ps1 "PKITools 1.6"
  [2]: https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16 "KB5014754: Certificate-based authentication changes on Windows domain controllers"

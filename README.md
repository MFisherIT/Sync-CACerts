# Sync-CACerts
Use a Group Managed Serice Account (gMSA) with a scheduled task to create on-premise Active Directory placeholder computer objects for Entra-Joined devices containing the serial numbers of recently issued certificates.

# Requirements
+ Active Directory
+ Active Directory Certificate Services
+ Microsoft Graph
  + with PowerShell module
+ Entra ID App Registration
  + with matching local certificate
+ [BladeFireLight's Get-IssuedCertificate function][1]

  [1]: https://www.powershellgallery.com/packages/PKITools/1.6/Content/Get-IssuedCertificates.ps1 "PKITools 1.6"

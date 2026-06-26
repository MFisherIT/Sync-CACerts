<#try scheduled task as Group Managed service account
 https://stackoverflow.com/questions/66604102/start-powershell-as-a-group-managed-service-account

 $principal=New-ScheduledTaskPrincipal -UserId NDES.gMSA$ -LogonType Password -RunLevel Highest
 set-ScheduledTask -TaskName "sync certs" -Principal $principal
 Or with windows 2019 just choose the group managed service account from AD. If delegation is setup correctly then it will not prompt for password.
#>
function Get-IssuedCertificate
{
    <#
        .SYNOPSIS
        Get Issued Certificate data from one or more certificate athorities.

        .DESCRIPTION
        Can get various certificate fileds from the Certificate Authority database. Usfull for exporting certificates or checking what is about to expire

        .PARAMETER ExpireInDays
        Maximum number of days from now that a certificate will expire. (Default: 21900 = 60 years) Can be a negative numbe to check for recent expirations

        .PARAMETER CAlocation
        Certificate Authority location string "computername\CAName" (Default gets location strings from Current Domain)

        .PARAMETER Properties
        Fields in the Certificate Authority Database to Export

        .PARAMETER CertificateTemplateOid
        Filter on Certificate Template OID (use Get-CertificateTemplateOID)

        .PARAMETER CommonName
        Filter by Issued Common Name

        .EXAMPLE
        Get-IssuedCertificate -ExpireInDays 14
        Gets all Issued Certificates Expireing in the next two weeks

        .EXAMPLE
        Get-IssuedCertificate -ExpireInDays -7
        Gets all Issued Certificates that Expired last week

        .EXAMPLE
        Get-IssuedCertificate -CAlocation CA1\MyCA
        Gets all Certificates Issued by CA1

        .EXAMPLE
        Get-IssuedCertificate -Properties 'Issued Common Name', 'Certificate Hash'
        Gets all Issued Certificates and outputs only the Common name and thumbprint

        .EXAMPLE
        Get-IssuedCertificate -CommonName S1, S2.contoso.com
        Gets Certificats issued to S1 and S2.contoso.com

        .EXAMPLE
        $DSCCerts = Get-IssuedCertificate -CertificateTemplateOid (Get-CertificateTemplateOID -Name 'DSCTemplate') -Properties 'Issued Common Name', 'Binary Certificate'
        foreach ($cert in $DSCCerts)
        {
            set-content -path "c:\certs\$($cert.'Issued Common Name').cer" -Value $cert.'Binary Certificate' -Encoding Ascii
        }
        Get all certificates issued useing the DSCTemplate template and save them to the folder c:\certs named for the Common name of the certificate

        .LINK
        https://www.powershellgallery.com/packages/PKITools/1.6/Content/Get-IssuedCertificates.ps1
   #>


    [CmdletBinding()]
    Param (

        # Maximum number of days from now that a certificate will expire. (Default: 21900 = 60 years)
        [Int]
        $ExpireInDays = 21900,

        # Certificate Authority location string "computername\CAName" (Default gets location strings from Current Domain)
        [String[]]
        $CAlocation = ((certutil | Select-String 'Config:\s*"(.*)"$').Matches[0].Groups[1].Value),

        # Fields in the Certificate Authority Database to Export
        [String[]]
        $Properties = (
            'Issued Common Name',
            'Serial Number',
            'Certificate Expiration Date',
            'Certificate Effective Date',
            #'Issued Email Address',
            'Issued Request ID',
            #'Certificate Hash',
            #'Request Disposition',
            #'Request Disposition Message',
            #'Requester Name',
            'Binary Certificate',
            'Certificate Template'
        ),

        # Filter on Certificate Template OID (use Get-CertificateTemplateOID)
        [AllowNull()]
        [String]
        $CertificateTemplateOid,

        # Filter by Issued Common Name
        [AllowNull()]
        [String]
        $CommonName
    )

    foreach ($Location in $CAlocation)
    {
        $CaView = New-Object -ComObject CertificateAuthority.View
        $null = $CaView.OpenConnection($Location)
        $CaView.SetResultColumnCount($Properties.Count)

        #region SetOutput Colum
        foreach ($item in $Properties)
        {
            $index = $CaView.GetColumnIndex($false, $item)
            $CaView.SetResultColumn($index)
        }
        #endregion

        #region Filters
        $CVR_SEEK_EQ = 1
        $CVR_SEEK_LT = 2
        $CVR_SEEK_GT = 16

        #region filter expiration Date
        $index = $CaView.GetColumnIndex($false, 'Certificate Expiration Date')
        $now = Get-Date
        $expirationdate = $now.AddDays($ExpireInDays)
        if ($ExpireInDays -gt 0)
        {
            $CaView.SetRestriction($index, $CVR_SEEK_GT, 0, $now)
            $CaView.SetRestriction($index, $CVR_SEEK_LT, 0, $expirationdate)
        }
        else
        {
            $CaView.SetRestriction($index, $CVR_SEEK_LT, 0, $now)
            $CaView.SetRestriction($index, $CVR_SEEK_GT, 0, $expirationdate)
        }
        #endregion filter expiration date

        #region Filter Template
        if ($CertificateTemplateOid)
        {
            $index = $CaView.GetColumnIndex($false, 'Certificate Template')
            $CaView.SetRestriction($index, $CVR_SEEK_EQ, 0, $CertificateTemplateOid)
        }
        #endregion

        #region Filter Issued Common Name
        if ($CommonName)
        {
            $index = $CaView.GetColumnIndex($false, 'Issued Common Name')
            $CaView.SetRestriction($index, $CVR_SEEK_EQ, 0, $CommonName)
        }
        #endregion

        #region Filter Only issued certificates
        # 20 - issued certificates
        $CaView.SetRestriction($CaView.GetColumnIndex($false, 'Request Disposition'), $CVR_SEEK_EQ, 0, 20)
        #endregion

        #endregion

        #region output each retuned row
        $CV_OUT_BASE64HEADER = 0
        $CV_OUT_BASE64 = 1
        $RowObj = $CaView.OpenView()

        while ($RowObj.Next() -ne -1)
        {
            $Cert = New-Object -TypeName PsObject
            $ColObj = $RowObj.EnumCertViewColumn()
            $null = $ColObj.Next()
            do
            {
                $displayName = $ColObj.GetDisplayName()
                # format Binary Certificate in a savable format.
                if ($displayName -eq 'Binary Certificate')
                {
                    $Cert | Add-Member -MemberType NoteProperty -Name $displayName -Value $($ColObj.GetValue($CV_OUT_BASE64HEADER)) -Force
                }
                else
                {
                    $Cert | Add-Member -MemberType NoteProperty -Name $displayName -Value $($ColObj.GetValue($CV_OUT_BASE64)) -Force
                }
            }
            until ($ColObj.Next() -eq -1)
            Clear-Variable -Name ColObj

            $Cert
        }
    }
}

function ConvertTo-ReverseByteOrder
{
    param
    (
        [string]
        $syncCaCertsCertificateSerialNumber
    )
    #https://www.reddit.com/r/sysadmin/comments/urmvi3/comment/i8ynae4/ xxdcmast & Androktasie
    #split string into byte array pairs
    $splitCertificateSerialNumber = $syncCaCertsCertificateSerialNumber -split '(..)' -ne ''
    #Join the bytes into string
    return ($splitCertificateSerialNumber[-1.. - $splitCertificateSerialNumber.Length] -join '')
}
$errorCount = 0
try
{
    if (-not (Test-Path -Path "$Env:Public\Documents\SyncCaCerts\") )
    {
        New-Item -ItemType Directory -Name SyncCaCerts -Path "$Env:Public\Documents\" -ErrorAction stop | Out-Null
    }
    $logFilePath = "$Env:Public\Documents\SyncCaCerts\$(get-date -Format 'yy-MM-dd_HHmmss').txt"
    # logFileHeader is a script is is re-evualated each time the logFileHeader is called; thus, using it in the log message allows for updated information; like timestamp.
    $logFileHeader = { "$(get-date -Format 'yyyy-MM-ddTHH:mm:ss.fffZ') $env:COMPUTERNAME LEEF:2.0|Microsoft|PowerShell|$($PSVersionTable.PSVersion.ToString())|" }
    "<000>1 $(& $logFileHeader)00000000|;|Message=StartingLog;LogFilePath=$logFilePath" | Tee-Object -FilePath $logFilePath -Append

    try
    {
        $certCN='Sync-CACerts'
        $certLocation='\LocalMachine\My\'
        $syncCaCertsCertificate=$null
        "<000>1 $(& $logFileHeader)00000002|;|Message=Locating a valid certificate in $certLocation with a subject like CN=$certCN*...;" | Tee-Object -FilePath $logFilePath -Append
        $syncCaCertsCertificate=(
            (Get-ChildItem -Recurse Cert:$certLocation).where{
                $_.NotAfter -gt (get-date) -and $_.Subject -like "CN=$certCN*"
            }|Sort-Object -Property NotAfter -Descending
        )[0]
        if ($null -eq $syncCaCertsCertificate) {
            Throw "Faild to locate a valid certificate in $certLocation with a subject like CN=$certCN*!"
        }
        "<000>1 $(& $logFileHeader)00000004|;|Message=Located a valid certificate in $certLocation with a CN=$certCN;$syncCaCertsCertificate" | Tee-Object -FilePath $logFilePath -Append
    }
    catch
    {
        $errorCount++
        "<000>1 $(& $logFileHeader)F0000008|;|Message=We failed to find a certificate matching $certCN;PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
        $xmlBody = "<prtg><Text>$logMessage</Text><Error>1</Error></prtg>"
        Invoke-WebRequest -UseBasicParsing -Uri "https://yourPRTGprobe.your.domain:5051/4C3235DE-E88F-434B-AB57-11719E0A1D3D" -Method Post -ContentType application/xml -Body $xmlbody -ErrorAction SilentlyContinue
        exit 1
    }

    $MgDeviceManagementManagedDeviceFilter = @"
ManagedDeviceOwnerType eq 'company' and
ComplianceState eq 'compliant' and
(OperatingSystem eq 'windows' or OperatingSystem eq 'macOS')
"@
    #'objectSid,DNSHostName,userAccountControl,servicePrincipalName,altSecurityIdentities'
    $adComputerProperties = @('objectSid', 'DNSHostName', 'userAccountControl', 'servicePrincipalName', 'altSecurityIdentities', 'networkAddress')

    $mgAzureADJoinedManagedDeviceProperties = ("Id", "DeviceName", "Notes", "EthernetMacAddress")
    try
    {
        $connectMgGraph = Connect-MgGraph -ClientId 68944832-08c4-4f1e-95f2-2959992dba99 -TenantId dec17208-0098-4472-9a36-2d8016988ea3 -Certificate $syncCaCertsCertificate -NoWelcome -ErrorAction Stop
        "<000>1 $(& $logFileHeader)00000010|;|Message=$connectMgGraph;Get-MgContext=$((Get-MgContext).Scopes -join ',')" | Tee-Object -FilePath $logFilePath -Append
    }
    catch
    {
        $errorCount++
        "<000>1 $(& $logFileHeader)F0000011|;|Message=There was an issue attempting to connect to Microsoft Graph;PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
        $xmlBody = "<prtg><Text>$logMessage</Text><Error>1</Error></prtg>"
        Invoke-WebRequest -UseBasicParsing -Uri "https://yourPRTGprobe.your.domain:5051/4C3235DE-E88F-434B-AB57-11719E0A1D3D" -Method Post -ContentType application/xml -Body $xmlbody -ErrorAction SilentlyContinue
        exit 1
    }

    #microsoft Graph deviece management manged device propteries list:
    #$mgProperties=("ActivationLockBypassCode","AndroidSecurityPatchLevel","AzureAdDeviceId","AzureAdRegistered","ComplianceGracePeriodExpirationDateTime","ComplianceState","ConfigurationManagerClientEnabledFeatures","DeviceActionResults","DeviceCategory","DeviceCategoryDisplayName","DeviceCompliancePolicyStates","DeviceConfigurationStates","DeviceEnrollmentType","DeviceHealthAttestationState","DeviceName","DeviceRegistrationState","EasActivated","EasActivationDateTime","EasDeviceId","EmailAddress","EnrolledDateTime","EthernetMacAddress","ExchangeAccessState","ExchangeAccessStateReason","ExchangeLastSuccessfulSyncDateTime","FreeStorageSpaceInBytes","Iccid","Id","Imei","IsEncrypted","IsSupervised","JailBroken","LastSyncDateTime","ManagedDeviceName","ManagedDeviceOwnerType","ManagementAgent","ManagementCertificateExpirationDate","Manufacturer","Meid","Model","Notes","OperatingSystem","OSVersion","PartnerReportedThreatState","PhoneNumber","PhysicalMemoryInBytes","RemoteAssistanceSessionErrorDetails","RemoteAssistanceSessionUrl","RequireUserEnrollmentApproval","SerialNumber","SubscriberCarrier","TotalStorageSpaceInBytes","Udid","UserDisplayName","UserId","UserPrincipalName","Users","WiFiMacAddress")

    try
    {
        $mgManagedDevices = Get-MgDeviceManagementManagedDevice -Filter $MgDeviceManagementManagedDeviceFilter -ErrorAction Stop
        #).where({$_.ManagedDeviceOwnerType -eq 'company' -and $_.OperatingSystem -like '*windows*' -and $_.ComplianceState -eq 'compliant'})
    }
    catch
    {
        $errorCount++
        "#000$(& $logFileHeader)F0000020|;|Message=There was an error while attempting to retreve the managed devices;PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
        $xmlBody = "<prtg><Text>$logMessage</Text><Error>1</Error></prtg>"
        Invoke-WebRequest -UseBasicParsing -Uri "https://yourPRTGprobe.your.domain:5051/4C3235DE-E88F-434B-AB57-11719E0A1D3D" -Method Post -ContentType application/xml -Body $xmlbody -ErrorAction SilentlyContinue
        exit 1
    }

    try
    {
        $theIssuedCerts = Get-IssuedCertificate -CAlocation (certutil -sid 24 | Select-String 'Config:\s*"(.*)"$').Matches[0].Groups[1].Value `
            -CertificateTemplateOid '1.3.6.1.4.1.311.21.8.2632279.414131.9916032.7443383.1093578.213.5128369.6206644' `
            -Properties 'Issued Common Name', 'Certificate Template', 'Serial Number', 'Certificate Expiration Date'
    }
    catch
    {
        $errorCount++
        "<000>1 $(& $logFileHeader)F0000030|;|Message=There was an error while attempting to retreve the certificates from the CA;PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
        $xmlBody = "<prtg><Text>$logMessage</Text><Error>1</Error></prtg>"
        Invoke-WebRequest -UseBasicParsing -Uri "https://yourPRTGprobe.your.domain:5051/4C3235DE-E88F-434B-AB57-11719E0A1D3D" -Method Post -ContentType application/xml -Body $xmlbody -ErrorAction SilentlyContinue
        exit 1
    }

    try
    {
        $theLatestIssuedAzureADJoindCerts = @()
        foreach ($issuedCert in ($theIssuedCerts.where({ $_.'Issued Common Name' -notlike '*.your.domain' }) | Group-Object 'Issued Common Name') )
        {
            $theLatestIssuedAzureADJoindCerts += $issuedCert.Group | Sort-Object 'Certificate Expiration Date' | Select-Object -Last 5
        }
    }
    catch
    {
        $errorCount++
        "<050>1 $(& $logFileHeader)F0000040|;|Message=While filtering the certificates, there was an error attempting to sort, and select the certificates grouped by 'Issued Common Name';PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
        $xmlBody = "<prtg><Text>$logMessage</Text><Error>1</Error></prtg>"
        Invoke-WebRequest -UseBasicParsing -Uri "https://yourPRTGprobe.your.domain:5051/4C3235DE-E88F-434B-AB57-11719E0A1D3D" -Method Post -ContentType application/xml -Body $xmlbody -ErrorAction SilentlyContinue
        exit 1
    }

    #region ForLatestIssuedCertificate
    $azureADJoinedComputer = $null
    foreach ($latestIssuedCert in $theLatestIssuedAzureADJoindCerts )
    {
        #region GatherazureADJoinedComputerObjects
        "<010>1 $(& $logFileHeader)00000050|;|Message=Found cert for: $($latestIssuedCert.'Issued Common Name') with serial number of: $($latestIssuedCert.'Serial Number')" | Tee-Object -FilePath $logFilePath -Append
        try
        {
            $adComputer = Get-ADComputer -Server YourDomainController -Filter "name -eq '$($latestIssuedCert.'Issued Common Name'.split('.')[0])'" -Properties $adComputerProperties -ErrorAction Stop
        }
        catch
        {
            $errorCount++
            "<010>1 $(& $logFileHeader)F0000060|;|Message=There was an error while attempting to retreve the AD Computer;adComputer=$($latestIssuedCert.'Issued Common Name');PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
            $logMessage = "#$(get-date -Format 'yy-MM-dd_HH:mm:ss') :: There was an error while attempting to retreve the AD Computer"
            continue
        }

        try
        {
            $mgManagedDevice = ($mgManagedDevices.where({ $_.DeviceName -eq $latestIssuedCert.'Issued Common Name' }))[0]
        }
        catch
        {
            $errorCount++
            "<210>1 $(& $logFileHeader)F0000070|;|Message=There was an error while attempting filter managed devices;PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
            continue
        }

        try
        {
            IF ( $null -ne $mgManagedDevice )
            {
                $mgAzureADJoinedManagedDevice = Get-MgDeviceManagementManagedDevice -ManagedDeviceId $mgManagedDevice.Id -Property $mgAzureADJoinedManagedDeviceProperties -ErrorAction Stop
            }
            else
            { $mgAzureADJoinedManagedDevice = $null }
        }
        catch
        {
            $errorCount++
            "<100>1 $(& $logFileHeader)F0000080|;|Message=There was an error while attempting to retreve the managed device;PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
            continue
        }

        #region FoundMatchingADComputer
        if ( $null -ne $adComputer -and $null -eq $adComputer.DNSHostName -and $null -ne $mgAzureADJoinedManagedDevice)
        {
            "<103>1 $(& $logFileHeader)00000090|;|Message=The matching AD computer $($adComputer.Name) with SID of: $($adComputer.objectSid) and Intune device with ID of: $($mgAzureADJoinedManagedDevice.Id)" | Tee-Object -FilePath $logFilePath -Append
            try
            {
                $azureADJoinedComputer = [PSCustomObject]@{
                    'issuedCert'    = $latestIssuedCert
                    'ADComputer'    = $adComputer
                    'ManagedDevice' = $mgAzureADJoinedManagedDevice
                }
            }
            catch
            {
                $errorCount++
                "<000>1 $(& $logFileHeader)F0000100|;|Message=There was an error while attempting to store the cert, computer, and device in PSCustomObject azureADJoinedComputer;PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
                continue
            }
        }
        #endregion FoundMatchingADComputer
        #region CreateADcomptuer
        elseif ( $null -ne $mgAzureADJoinedManagedDevice -and $mgAzureADJoinedManagedDevice.count -eq 1 )
        {
            "<710>1 $(& $logFileHeader)00000110|;|Message=No matching AD computer with Name of: $($latestIssuedCert.'Issued Common Name'). Found matching Intune device with ID of: $($mgAzureADJoinedManagedDevice.Id). Creating on-premise AD computer object for certificate authentication" | Tee-Object -FilePath $logFilePath -Append

            if ( $null -eq $mgAzureADJoinedManagedDevice.Notes )
            {
                try
                {
                    $adComputer = New-ADComputer -Name $latestIssuedCert.'Issued Common Name' -SAMAccountName $latestIssuedCert.'Issued Common Name' -DisplayName $latestIssuedCert.'Issued Common Name' `
                        -Enabled:$true -ServicePrincipalNames @("HOST/$($latestIssuedCert.'Issued Common Name')") `
                        -Server YourDomainController -PassThru `
                        -Path 'OU=Computers,OU=dot1x,OU=yourOUname,DC=your,DC=domain' -AccountPassword $NULL -PasswordNotRequired:$false
                }
                catch
                {
                    $errorCount++
                    "<010>1 $(& $logFileHeader)F0000120|;|Message=There was an error while attempting to create the new AD computer (without a description);PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
                    continue
                }
            }
            else
            {
                try
                {
                    $adComputer = New-ADComputer -Name $latestIssuedCert.'Issued Common Name' -SAMAccountName $latestIssuedCert.'Issued Common Name' -DisplayName $latestIssuedCert.'Issued Common Name' `
                        -Enabled:$true -ServicePrincipalNames @("HOST/$($latestIssuedCert.'Issued Common Name')") `
                        -Description $mgAzureADJoinedManagedDevice.Notes -Server YourDomainController -PassThru `
                        -Path 'OU=Computers,OU=dot1x,OU=yourOUname,DC=your,DC=domain' -AccountPassword $NULL -PasswordNotRequired:$false
                }
                catch
                {
                    $errorCount++
                    "<710>1 $(& $logFileHeader)F0000130|;|Message=There was an error while attempting to create the new AD computer (with a description);PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
                    continue
                }
            }
            $NumberOfChecksForADComputer = -1
            while (($NumberOfChecksForADComputer++ -gt 0 -and $NumberOfChecksForADComputer -le 3) -and -not $WhatIfPreference)
            {
                "<001>1 $(& $logFileHeader)00000140|;|Message=Trying to get the AS computer $($adComputer.Name) from AD. This is attempt number $NumberOfChecksForADComputer." | Tee-Object -FilePath $logFilePath -Append
                try
                {
                    $adComputer = Get-ADComputer -Server YourDomainController -Identity $adComputer.Name -Properties $adComputerProperties -ErrorAction Stop -WarningAction Stop
                    $NumberOfChecksForADComputer = 0
                }
                catch
                {
                    "<001>1 $(& $logFileHeader)00000150|;|Message=Failed to get the AD Computer $($adComputer.Name). Sleeping for 90 milliseconds and trying again." | Tee-Object -FilePath $logFilePath -Append
                    Start-Sleep -Milliseconds 90
                }
            }
            "<801>1 $(& $logFileHeader)00000160|;|Message=Found the AD Computer $($adComputer.Name)." | Tee-Object -FilePath $logFilePath -Append
            try
            {
                $mac = [string]::Format("{0}.{1}.{2}", ($mgAzureADJoinedManagedDevice.EthernetMacAddress[0..3] -join ''), ($mgAzureADJoinedManagedDevice.EthernetMacAddress[4..7] -join ''), ($mgAzureADJoinedManagedDevice.EthernetMacAddress[8..11] -join ''))
                "<007>1 $(& $logFileHeader)00000170|;|Message=parsed the networkAddress of: $mac" | Tee-Object -FilePath $logFilePath -Append
            }
            catch
            {
                $errorCount++
                "<007>1 $(& $logFileHeader)F0000180|;|Message=Faild to parse the EthernetMacAddress;PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
            }
            #region AddNewADComptuerToGroups
            try
            {
                if ($adComputer.Name -like 'MTR-*')
                {
                    "<007>1 $(& $logFileHeader)00000182|;|Message=The name `"$($adComputer.name)`" is like MTR-, so adding as members of to group '802.1xAuth-Voice'" | Tee-Object -FilePath $logFilePath -Append
                    Add-ADGroupMember -Server YourDomainController -Identity '802.1xAuth-Voice' -Members "$($adComputer.name)$"
                }
            }
            catch
            {
                $errorCount++
                "<007>1 $(& $logFileHeader)F0000186|;|Message=There was an error while attempting to add the computer as a member of group '802.1xAuth-Voice'.;PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
            }
            #endregion AddNewADComptuerToGroups
            #region SetNewADComptuerPrimaryGroupID
            try
            {
                if ('CN=802.1xAuth,OU=Users,OU=dot1x,OU=yourOUname,DC=your,DC=domain' -notin $adComputer.MemberOf)
                {
                    "<007>1 $(& $logFileHeader)00000188|;|Message=Setting the priamry group ID of $($adComputer.name)$ to: 1597313 (802.1xAuth) and networkAddress to $mac" | Tee-Object -FilePath $logFilePath -Append
                    Add-ADGroupMember -Server YourDomainController -Identity '802.1xAuth' -Members "$($adComputer.name)$" | Out-Null
                    "<007>1 $(& $logFileHeader)00000188|;|Message=Setting the priamry group ID of $($adComputer.name)$ to: 1597313 (802.1xAuth) and networkAddress to $mac" | Tee-Object -FilePath $logFilePath -Append
                    $adComputer = Set-ADComputer -Server YourDomainController -Identity $adComputer.name -SAMAccountName $adComputer.SamAccountName -Replace @{primaryGroupID = 1597313; networkAddress = $mac } -PassThru
                }
            }
            catch
            {
                $errorCount++
                "<009>1 $(& $logFileHeader)F0000190|;|Message=There was an error while attempting to set the computer primary group.;PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
                continue
            }
            #endregion SetNewADComptuerPrimaryGroupID
            try
            {
                $adComputer = Get-ADComputer -Server YourDomainController -Identity $adComputer.Name -Properties $adComputerProperties -ErrorAction Stop -WarningAction Stop
                Remove-ADComputer -Identity "Domain Computers" -Members $adComputer -Confirm:$false -ErrorAction Stop
            }
            catch
            {
                $errorCount++
                "<001>1 $(& $logFileHeader)F0000200|;|Message=There was an error while attempting to remove the ad computer from the Domain Computers;PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
                continue
            }
            $azureADJoinedComputer = [PSCustomObject]@{
                'issuedCert'    = $latestIssuedCert
                'ADComputer'    = $adComputer
                'ManagedDevice' = $mgAzureADJoinedManagedDevice
            }
        }
        #endregion CreateADcomptuer
        #endregion GatherazureADJoinedComputerObjects
        #region SetPropertiesOfADComputerObject
        #region CertificateAltSecurityIdentities
        if ($null -ne $azureADJoinedComputer -and $null -ne ($latestIssuedCert.'Serial Number') -and $null -ne ($azureADJoinedComputer.ADComputer.Name) )
        {
            $intendedADComputerServicePrinicpalName = "X509:<I>DC=domain,DC=your,CN=yourERCA<SR>$(ConvertTo-ReverseByteOrder -syncCaCertsCertificateSerialNumber $latestIssuedCert.'Serial Number')"
            IF ( $intendedADComputerServicePrinicpalName -notin $azureADJoinedComputer.ADComputer.altSecurityIdentities )
            {
                "<036>1 $(& $logFileHeader)00000210|;|Message=The certificate serial was not found in the altSecurityIdentities. Replacing $($azureADJoinedComputer.ADComputer.altSecurityIdentities) with $intendedADComputerServicePrinicpalName." | Tee-Object -FilePath $logFilePath -Append
                try
                {
                    #how many altSecurityIdentities are there?
                    if ($azureADJoinedComputer.ADComputer.altSecurityIdentities.count -gt 5)
                    {
                        # if more than too many remove last 2? -- don't know form just looking at ad how old they are
                        # gather certs that are part of the ad computer item
                        $certsListInSecurityIds = @()
                        foreach ($altIdSerialNumber in ($azureADJoinedComputer.ADComputer.altSecurityIdentities.foreach({ (select-string -InputObject $_ -Pattern '<SR>(\d*|\w*)$' -AllMatches).Matches.Groups[1].Value })) )
                        {
                            $oneCertIssuedAndListedInSecIds = $theIssuedCerts.where({ $_.'Issued Common Name' -eq (ConvertTo-ReverseByteOrder -syncCaCertsCertificateSerialNumber $altIdSerialNumber) })
                            if ( $null -ne $oneCertIssuedAndListedInSecIds )
                            {
                                $certsListInSecurityIds += $oneCertIssuedAndListedInSecIds
                                $oneCertIssuedAndListedInSecIds = $null
                            }
                        }
                        # if the cert expired remove and re-check count
                        # keep only three newest issued certs
                        #select the certifictes to remove
                        $certsToRemove += $listedIssuedCert | Sort-Object 'Certificate Expiration Date' | Select-Object -First 3
                        foreach ($certToRemove in $certsToRemove)
                        {
                            $serialToRemove = ConvertTo-ReverseByteOrder -syncCaCertsCertificateSerialNumber $certsToRemove.'Serial Number'
                            Set-ADComputer -Identity $azureADJoinedComputer.ADComputer.Name -Remove @{altSecurityIdentities = "X509:<I>DC=domain,DC=your,CN=yourERCA<SR>$serialToRemove" }
                        }
                    }
                    #Add the serail number ID for current certificate.
                    Set-ADComputer $azureADJoinedComputer.ADComputer.Name -Add @{altSecurityIdentities = $intendedADComputerServicePrinicpalName } -Server YourDomainController -Verbose
                }
                catch
                {
                    $errorCount++
                    "<036>1 $(& $logFileHeader)F0000220|;|Message=There was an error while attempting to replace the adcomputers altSecurityIdentities;PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
                    continue
                }
            }
            else
            {
                "<036>1 $(& $logFileHeader)00000230|;|Message=Matched the certificate serial of:$intendedADComputerServicePrinicpalName and altSecurityIdentities of $($azureADJoinedComputer.ADComputer.altSecurityIdentities)." | Tee-Object -FilePath $logFilePath -Append
            }
        }
        #endregion CertificateAltSecurityIdentities

        #region SetADComputerMAC
        if ($null -ne $azureADJoinedComputer)
        {
            try
            {
                "<036>1 $(& $logFileHeader)00000232|;|Message=Parsing the ManagedDevice's EthernetMacAddress" | Tee-Object -FilePath $logFilePath -Append
                if ($null -ne $azureADJoinedComputer.ManagedDevice -and $null -ne $azureADJoinedComputer.ManagedDevice.EthernetMacAddress)
                {
                    $mac = [string]::Format("{0}.{1}.{2}", ($azureADJoinedComputer.ManagedDevice.EthernetMacAddress[0..3] -join ''), ($azureADJoinedComputer.ManagedDevice.EthernetMacAddress[4..7] -join ''), ($azureADJoinedComputer.ManagedDevice.EthernetMacAddress[8..11] -join ''))
                }
            }
            catch
            {
                $errorCount++
                "<036>1 $(& $logFileHeader)F0000238|;|Message=Error Parsing the ManagedDevice's EthernetMacAddress" | Tee-Object -FilePath $logFilePath -Append
            }
    
            try
            {
                if ($azureADJoinedComputer.ADComputer.networkAddress -notcontains $mac)
                {
                    "<007>1 $(& $logFileHeader)00000240|;|Message=Setting networkAddress to: $mac" | Tee-Object -FilePath $logFilePath -Append
                    if ($NULL -ne $azureADJoinedComputer.ADComputer.networkAddress -and $azureADJoinedComputer.ADComputer.networkAddress -ne $mac)
                    {
                        $adComputer = Set-ADComputer -Server YourDomainController -Identity $azureADJoinedComputer.ADComputer.name -Replace @{networkAddress = $mac } -PassThru
                        $azureADJoinedComputer.ADComputer = Get-ADComputer -Server YourDomainController -Identity $adComputer.Name -Properties $adComputerProperties -ErrorAction Stop -WarningAction Stop
                    }
                }
            }
            catch
            {
                $errorCount++
                "<007>1 $(& $logFileHeader)F0000250|;|Message=Faild to parse the EthernetMacAddress or set the MAC address;PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
            }
        }
        #endregion SetADComputerMAC

        #region AlterADComputerGroupMembership
        if ( $null -ne $azureADJoinedComputer.ADComputer `
                -and 'CN=802.1xAuth-Voice,OU=Users,OU=dot1x,OU=yourOUname,DC=your,DC=domain' -notin $azureADJoinedComputer.ADComputer.MemberOf `
                -and $azureADJoinedComputer.ADComputer.Name -like 'MTR-*'
        )
        {
            try
            {
                "<007>1 $(& $logFileHeader)00000270|;|Message=The name `"$($azureADJoinedComputer.ADComputer.name)`" is like MTR-, so adding as members of to group '802.1xAuth-Voice'" | Tee-Object -FilePath $logFilePath -Append
                Add-ADGroupMember -Server YourDomainController -Identity '802.1xAuth-Voice' -Members "$($azureADJoinedComputer.ADComputer.name)$"
            }
            catch
            {
                $errorCount++
                "<007>1 $(& $logFileHeader)F0000280|;|Message=There was an error while attempting to groups.;PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
            }
        }

        try
        {
            if ($null -ne $azureADJoinedComputer -and $azureADJoinedComputer.ADComputer.primaryGroupID -ne 1597313)
            {
                "<007>1 $(& $logFileHeader)00000290|;|Message=Setting the priamry group ID of $($azureADJoinedComputer.ADComputer.name)$ to: 1597313 (802.1xAuth)" | Tee-Object -FilePath $logFilePath -Append
                if ('CN=802.1xAuth,OU=Users,OU=dot1x,OU=yourOUname,DC=your,DC=domain' -in $azureADJoinedComputer.ADComputer.MemberOf)
                {
                    Remove-ADGroupMember -Identity '802.1xAuth' -Members "$($azureADJoinedComputer.ADComputer.name)$"
                }
                $azureADJoinedComputer.ADComputer = Set-ADComputer -Server YourDomainController -Identity $azureADJoinedComputer.ADComputer.name -Replace @{primaryGroupID = 1597313 } -PassThru
                $azureADJoinedComputer.ADComputer = Get-ADComputer -Server YourDomainController -Identity $azureADJoinedComputer.ADComputer.Name -Properties $adComputerProperties -ErrorAction Stop -WarningAction Stop
            }
        }
        catch
        {
            $errorCount++
            "<009>1 $(& $logFileHeader)F0000300|;|Message=There was an error while attempting to set the $($azureADJoinedComputer.ADComputer.name) primary group.;PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
        }

        try
        {

            if ($null -ne $azureADJoinedComputer -and 'CN=Domain Computers,CN=Users,DC=your,DC=domain' -in $azureADJoinedComputer.ADComputer.MemberOf)
            {
                "<007>1 $(& $logFileHeader)00000310|;|Message=Removing $($azureADJoinedComputer.ADComputer.name)$ from domain computers group" | Tee-Object -FilePath $logFilePath -Append
                Remove-ADGroupMember -Server YourDomainController -Identity 'Domain Computers' -Members "$($azureADJoinedComputer.ADComputer.name)$"
            }
        }
        catch
        {
            $errorCount++
            "<009>1 $(& $logFileHeader)F0000320|;|Message=There was an error while emoving $($azureADJoinedComputer.ADComputer.name)$ from domain computers group.;PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
        }

        #endregion AlterADComputerGroupMembership
        #endregion SetPropertiesOfADComputerObject

        $azureADJoinedComputer = $null
    }
    #endregion ForLatestIssuedCertificate
}
catch
{
    $errorCount++
    "<000>1 $(& $logFileHeader)F0000990|;|Message=There was an error while processing;PSItem=$($PSItem.Exception.Message.replace(';',' '))" | Tee-Object -FilePath $logFilePath -Append
    $xmlBody = "<prtg><Text>$logMessage</Text><Error>1</Error></prtg>"
    Invoke-WebRequest -UseBasicParsing -Uri "https://yourPRTGprobe.your.domain:5051/4C3235DE-E88F-434B-AB57-11719E0A1D3D" -Method Post -ContentType application/xml -Body $xmlbody -ErrorAction SilentlyContinue
    exit 1
}
$xmlBody = "<prtg><result><channel>errorCount</channel><value>$errorCount</value></result><Error>0</Error></prtg>"
$webRequestStatus = Invoke-WebRequest -UseBasicParsing -Uri "https://yourPRTGprobe.your.domain:5051/4C3235DE-E88F-434B-AB57-11719E0A1D3D" -Method Post -ContentType application/xml -Body $xmlbody -ErrorAction SilentlyContinue
"<000>1 $(& $logFileHeader)00000999|;|Message=script has compelted.;theLatestIssuedAzureADJoindCerts=$($theLatestIssuedAzureADJoindCerts.Count);mgManagedDevices=$($mgManagedDevices.Count);errorCount=$errorCount;webRequestStatus=$webRequestStatus" | Tee-Object -FilePath $logFilePath -Append
exit 0

Function Get-Catalog
{
    param
    (
        [string]$identityURI,
        [Parameter(Mandatory)]
        [pscredential]$Credential
    )
    $credJson = @{"auth" = @{"RAX-KSKEY:apiKeyCredentials" =  @{"username" = $Credential.UserName; "apiKey" = $Credential.GetNetworkCredential().Password}}} | convertTo-Json
    $catalog = Invoke-RestMethod -Uri $identityURI -Method POST -Body $credJson -ContentType application/json
    Return $catalog
}
Function Get-Authtoken
{
    Param
    ([Parameter(Mandatory)]$catalog)
    $authToken = @{"X-Auth-Token"=$catalog.access.token.id}
    Return $authToken
}
Function Get-API
{
    Param
    (
    [Parameter(Mandatory)]$catalog,
    [Parameter(Mandatory)]$region
    )
    $api = (($catalog.access.serviceCatalog | ? name -eq "cloudFiles").endpoints | ? region -match $region).PublicURL
    Return $api
}


function Get-TargetResource
{
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Container,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Region,
        [string]$identityURI = "https://identity.api.rackspacecloud.com/v2.0/tokens",
        [Parameter(Mandatory)]
        [pscredential]$Credential,
        [ValidateSet("File","Directory")]
        [string]$SyncMode = "File",
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,
        [string] $FileName,
        [Boolean]$MatchSource = $True,
        [ValidateSet("Present", "Absent")]
        [string] $Ensure = "Present"
    )
    
    #Presets
    if($FileName -match '/'){$FileName = $FileName -replace '/','\'}
    $catalog = Get-Catalog -identityURI $identityURI -Credential $Credential
    $authToken = Get-Authtoken -catalog $catalog
    $api = Get-API -catalog $catalog -region $region
    
    if($FileName -ne $null){$FullPath = ($FilePath, $FileName -join '\')}else{$FullPath = $FilePath}
    if(Test-Path($FullPath)){$Exist = $true}else{$Exist = $false}
    #Write-Output @PSBoundParameters
    Write-Verbose $PSBoundParameters
    $noHash = $false

    #Note: Hashmatching works for files under 5GB only.
    if(($Ensure -eq "Present") -and ($Exist -eq $true) -and ($MatchSource -eq $true))
    {
        Write-Verbose "Ensure is Present. FilePath exists. Testing MatchSource."
        if($SyncMode -eq "File")
        {
            if(Test-Path -Path $FullPath)
            {
                $fileheader = (Invoke-WebRequest -Uri $($api + "/$Container/$($file -replace '\\','/')") -Method HEAD -Headers $authToken).Headers
                $fileinfo = Get-ChildItem $FullPath
                Write-Verbose "SyncMode: $SyncMode File check: $($fileinfo.BaseName)"
                if(($fileheader.'Content-Length' -lt 5GB) -and ($fileinfo.Length -lt 5GB))
                {
                    $FileHash = (Get-FileHash $fileinfo.FullName -Algorithm MD5).hash.tolower()
                    $Hashmatch = $fileheader.ETag -match $FileHash
                    Write-Verbose "`n`tFileHash: $Filehash `n`tEtag: $($fileheader.ETag) `n`tHashmatch: $Hashmatch `n"
                }else{
                    Write-Verbose "The file $FileName is too large. Recommend Setting MatchSource to false for this file."
                    $noHash = $true
                }
            }
        }
        else
        {
            $Filelist = (Invoke-RestMethod -Uri $($api + "/$Container") -Method GET -Headers $authToken) -split "\n" | ? {($_ -notlike ".file-segments*") -and ($_ -notlike $null)}
            foreach ($file in $Filelist)
            {
                $fileheader = (Invoke-WebRequest -Uri $($api + "/$Container/$($file -replace '\\','/')") -Method HEAD -Headers $authToken).Headers
                Write-Verbose "SyncMode: $SyncMode. File to check: $file"
                if(($fileheader.'Content-Type' -match "directory") -and (Test-Path ($FullPath, $($file -replace '/','\') -join '\')) -and ((Get-Item ($FullPath, $($file -replace '/','\') -join '\')).Attributes -match "Directory"))
                    {Write-Verbose "Directory Path confirmed: $($FullPath, $($file -replace '/','\') -join '\') `n"}
                elseif(($fileheader.'Content-Type' -notmatch "directory") -and (Test-Path -Path ($FullPath, $($file -replace '/','\') -join '\')))
                {
                    $fileinfo = Get-ChildItem ($FullPath, $($file -replace '/','\') -join '\')
                    Write-Verbose "Hash check for local file: $($fileinfo.BaseName) `n"
                    if(($fileheader.'Content-Length' -lt 5GB) -and ($fileinfo.Length -lt 5GB))
                    {
                        $FileHash = (Get-FileHash $fileinfo.FullName -Algorithm MD5).hash.tolower()
                        $CheckHash = $fileheader.ETag -match $FileHash
                        if($Hashmatch -ne $false){$Hashmatch = $CheckHash}
                        Write-Verbose "`n`tFileHash: $Filehash `n`tEtag: $($fileheader.ETag) `n`tHashmatch: $CheckHash `n"
                    }
                    else
                    {
                        Write-Verbose "The File $($fileinfo.BaseName) is larger than 5GB and will not be matched to source."
                        $noHash = $true
                    }
                }else{
                    Write-Verbose "Content Missing: $file"
                    $Hashmatch = $false
                }
            }
            Write-Verbose "Filecheck Complete. Hashmatch: $Hashmatch NoHash: $noHash"
        }
        if($noHash -eq $null)
        {
            $SyncStatus = $Hashmatch
        }
        elseif(($noHash -eq $true) -and ($SyncMode -eq "File"))
        {
            Write-Verbose "File too large and SyncMode is File"
            $SyncStatus = $true
        }elseif($SyncMode -eq "File"){
            Write-Verbose "Hashmatch completed and SyncMode is File"
            $SyncStatus = $Hashmatch
        }elseif(($noHash -eq $true) -and ($SyncMode -eq "Directory"))
        {
            Write-Verbose "File or Files greater than 5GB found and SyncMode is Directory"
            $SyncStatus = $Hashmatch
        }else{
            Write-Verbose "Hashmatch completed and SyncMode is Directory"
            $SyncStatus = $Hashmatch
        }
    }
    elseif(($Ensure -eq "Present") -and (!($FileName)) -and ($Exist -eq $true))
    {
        $Filelist = (Invoke-RestMethod -Uri $($api + "/$Container") -Method GET -Headers $authToken) -split "\n" | ? {($_ -notlike ".file-segments*") -and ($_ -notlike $null)}
            foreach ($file in $Filelist)
            {
                Write-Verbose "Testing Path existence of: $file"
                if((Test-Path -Path ($FullPath, $($file -replace '/','\') -join '\')) -and ($SyncStatus -ne $false))
                {$SyncStatus = $true}else{$SyncStatus = $false}
            }
    }
    elseif(($Ensure -eq "Present") -and ($FileName -ne $null) -and ($Exist -eq $true))
        {$SyncStatus = $true}
    elseif(($Ensure -eq "Absent") -and (!($FileName)) -and ($Exist -eq $true))
    {
        $Filelist = (Invoke-RestMethod -Uri $($api + "/$Container") -Method GET -Headers $authToken) -split "\n" | ? {($_ -notlike ".file-segments*") -and ($_ -notlike $null)}
            foreach ($file in $Filelist)
            {
                Write-Verbose "Testing Path existence of: $file"
                if(!(Test-Path -Path ($FullPath, $($file -replace '/','\') -join '\')) -and ($SyncStatus -ne $false))
                {$SyncStatus = $true}else{$SyncStatus = $false}
            }
    }
    elseif(($Ensure -eq "Absent") -and ($Exist -eq $true))
        {$SyncStatus = $false}
    elseif($Ensure -eq "Absent")
        {$SyncStatus = $true}
    else
        {$SyncStatus = "unknown"}

    Write-Verbose "Sync Status is: $SyncStatus"

    Return @{
            Container = $Container;
            Ensure = $SyncStatus
            }
}

function Set-TargetResource
{
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Container,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Region,
        [string]$identityURI = "https://identity.api.rackspacecloud.com/v2.0/tokens",
        [Parameter(Mandatory)]
        [pscredential]$Credential,
        [ValidateSet("File","Directory")]
        [string]$SyncMode = "File",
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,
        [string] $FileName,
        [Boolean]$MatchSource = $True,
        [ValidateSet("Present", "Absent")]
        [string] $Ensure = "Present"
    )

    #Presets
    if($FileName -match '/'){$FileName = $FileName -replace '/','\'}
    $catalog = Get-Catalog -identityURI $identityURI -Credential $Credential
    $authToken = Get-Authtoken -catalog $catalog
    $api = Get-API -catalog $catalog -region $region
    
    if($FileName -ne $null){$FullPath = ($FilePath, $FileName -join '\')}else{$FullPath = $FilePath}
    if(Test-Path($FullPath)){$Exist = $true}else{$Exist = $false}

    #Note: Current configuration and restrictions block syncing of segmented files at this time.
    if($Ensure -eq "Present")
    {
        if($SyncMode -eq "File")
        {
            #If Item Exists, Remove it.
            Get-ChildItem -Path $FullPath -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            #Download item from Cloud Files
            (Invoke-WebRequest -Uri $($api + "/$Container/$($file -replace '\\','/')") -Method GET -Headers $authToken -OutFile $($FullPath))
        }
        else
        {
            if(!(Test-Path $FilePath)){New-Item -ItemType Directory -Path $FilePath}
            $Filelist = (Invoke-RestMethod -Uri $($api + "/$Container") -Method GET -Headers $authToken) -split "\n" | ? {($_ -notlike ".file-segments*") -and ($_ -notlike $null)}
            foreach ($file in $Filelist)
            {
                $fileheader = (Invoke-WebRequest -Uri $($api + "/$Container/$($file -replace '\\','/')") -Method HEAD -Headers $authToken).Headers
                if($fileheader.'Content-Type' -match "directory")
                {
                    Try
                    {
                        if((Test-Path ($FullPath, $($file -replace '/','\') -join '\')) -and ((Get-Item ($FullPath, $($file -replace '/','\') -join '\')).Attributes -match "Directory"))
                        {Write-Verbose "Directory Path Already created"}
                        else{
                        Write-Verbose "Directory Path Missing: $($FullPath, $($file -replace '/','\') -join '\')"
                        New-Item -ItemType Directory -Path ($FullPath, $($file -replace '/','\') -join '\') -Force
                        }
                    }
                    Catch
                    {
                        Write-Verbose "Invalid File Found. Removing and replacing file."
                        Get-Item -Path ($FullPath, $($file -replace '/','\') -join '\') | Remove-Item -Force
                        New-Item -ItemType Directory -Path ($FullPath, $($file -replace '/','\') -join '\') -Force
                    }Finally{
                        if((Get-Item ($FullPath, $($file -replace '/','\') -join '\')).Attributes -match "Directory")
                            {Write-Verbose "Directory Successfully Created: $($FullPath, $($file -replace '/','\') -join '\'))"}
                    }
                }
                elseif(($fileheader.'Content-Type' -notmatch "directory") -and (Test-Path ($FullPath, $($file -replace '/','\') -join '\')))
                {
                    $fileinfo = Get-ChildItem $($FullPath, $($file -replace '/','\') -join '\')
                    if(($fileheader.'Content-Length' -lt 5GB) -and ($fileinfo.Length -lt 5GB))
                    {
                        $FileHash = (Get-FileHash $fileinfo.FullName -Algorithm MD5).hash.tolower()
                        if(!($fileheader.ETag -match $FileHash))
                        {
                            $fileinfo | Remove-Item -Force -ErrorAction SilentlyContinue
                            (Invoke-WebRequest -Uri $($api + "/$Container/$($file -replace '\\','/')") -Method GET -Headers $authToken -OutFile $($fileinfo.FullName))
                        }
                    }
                    else{Write-Verbose "File $($fileinfo.BaseName) exists and is larger than 5GB. Not seeking Hash-match for $($file.FullName)"}
                }else{
                    Write-Verbose "File $File is missing. Downloading this file."
                    (Invoke-WebRequest -Uri $($api + "/$Container/$($file -replace '\\','/')") -Method GET -Headers $authToken -OutFile $($FullPath, $($file -replace '/','\') -join '\'))
                }
            }
        }
    }
    if(($Ensure -eq "Absent") -and ($Exist -eq $true))
    {
        Get-ChildItem $FullPath | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Test-TargetResource
{
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Container,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Region,
        [string]$identityURI = "https://identity.api.rackspacecloud.com/v2.0/tokens",
        [Parameter(Mandatory)]
        [pscredential]$Credential,
        [ValidateSet("File","Directory")]
        [string]$SyncMode = "File",
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,
        [string] $FileName,
        [Boolean]$MatchSource = $True,
        [ValidateSet("Present", "Absent")]
        [string] $Ensure = "Present"
    )
    $Status = Get-TargetResource @PSBoundParameters
    if($Status.Ensure -ne $true){Return $False}
    else{Return $true}
}



Export-ModuleMember -Function *-TargetResource

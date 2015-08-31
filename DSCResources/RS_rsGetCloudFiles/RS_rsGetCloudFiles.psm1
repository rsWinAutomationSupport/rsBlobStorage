Function Get-Catalog
{
    param
    (
        [Parameter(Mandatory)]
        [pscredential]$Credential
    )
    $identityURI = "https://identity.api.rackspacecloud.com/v2.0/tokens"
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
    $catalog = Get-Catalog -Credential $Credential
    $authToken = Get-Authtoken -catalog $catalog
    $api = Get-API -catalog $catalog -region $region
    
    if($FileName -ne $null){$FullPath = ($FilePath, $FileName -join '\')}else{$FullPath = $FilePath}
    if(Test-Path($FullPath)){$Exist = $true}else{$Exist = $false}
    #Write-Output @PSBoundParameters
    Write-Verbose $PSBoundParameters

    #Note: Hashmatching works for files under 5GB only.
    if(($Ensure -eq "Present") -and ($Exist -eq $true) -and ($MatchSource -eq $true))
    {
        if($SyncMode -eq "File")
        {
            $file = Get-ChildItem $FullPath
            Write-Verbose "File check: $($file.BaseName)"
            if($file.Length -lt 5GB)
            {
                $FileHash = (Get-FileHash $file.FullName -Algorithm MD5).hash.tolower()
                $ETag = (Invoke-WebRequest -Uri $($api + "/$Container/$($Filename -replace '\\','/')") -Method Head -Headers $authToken).Headers.ETag
                $Hashmatch = $ETag -match $FileHash
                Write-Verbose "`tFileHash: $Filehash `tEtag: $ETag `tHashmatch: $Hashmatch"
            }
            else
            {
                Write-Verbose "The file $FileName is too large. Recommend Setting MatchSource to false for this file."
                $noHash = $true
            }
        }
        else
        {
            $Filelist = (Invoke-RestMethod -Uri $($api + "/$Container") -Method GET -Headers $authToken) -split "\n" | ? {($_ -notlike ".file-segments*") -and ($_ -notlike $null)}
            foreach ($file in $Filelist)
            {
                #Write-output "File to check: $file"
                $FullPath = ($FilePath, $file -join '\')
                if(Test-Path -Path $FullPath)
                {
                    $file = Get-ChildItem $FullPath
                    Write-Verbose "File check: $($file.BaseName)"
                    if($file.Length -lt 5GB)
                    {
                        $FileHash = (Get-FileHash $file.FullName -Algorithm MD5).hash.tolower()
                        $ETag = (Invoke-WebRequest -Uri $($api + "/$Container/$($file.FullName.TrimStart($FilePath) -replace '\\','/')") -Method Head -Headers $authToken).Headers.ETag
                        $CheckHash = $ETag -match $FileHash
                        if(($Hashmatch -ne $null) -and ($Hashmatch -ne $false)){$Hashmatch = $CheckHash}
                        Write-Verbose "`tFileHash: $Filehash `tEtag: $ETag `tHashmatch: $CheckHash"
                    }
                    else
                    {
                        Write-Verbose "The File $($File.BaseName) is larger than 5GB and will not be matched to source."
                        $noHash = $true
                    }
                }else{
                    Write-Verbose "File Missing: $file"
                    $Hashmatch = $false
                }
            }
        }
        if($noHash -eq $null){$SyncStatus = $Hashmatch}
        elseif(($noHash -eq $true) -and ($SyncMode -eq "File"))
        {
            Write-Verbose "NoHash and SyncMode is File"
            $SyncStatus = $true
        }elseif($SyncMode -eq "File"){
            Write-Verbose "Hash and SyncMode is File"
            $SyncStatus = $false
        }elseif(($noHash -eq $true) -and ($SyncMode -eq "Directory"))
        {
            Write-Verbose "NoHash and SyncMode is Directory"
            $SyncStatus = $Hashmatch
        }else{
            Write-Verbose "Hash and SyncMode is Directory"
            $SyncStatus = $false
        }
    }
    elseif(($Ensure -eq "Present") -and ($Exist -eq $true))
        {$SyncStatus = $true}
    elseif(($Ensure -eq "Absent") -and ($Exist -eq $true))
        {$SyncStatus = $false}
    elseif($Ensure -eq "Absent")
        {$SyncStatus = $true}
    else
        {$SyncStatus = "unknown"}

    Write-Verbose "SyncMode Status is: $SyncStatus"

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
    $catalog = Get-Catalog -Credential $Credential
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
            (Invoke-WebRequest -Uri $($api + "/$Container/$($Filename -replace '\\','/')") -Method GET -Headers $authToken -OutFile $($FullPath))
        }
        else
        {
            if(!(Test-Path $FilePath)){New-Item -ItemType Directory -Path $FilePath}
            $Filelist = (Invoke-RestMethod -Uri $($api + "/$Container") -Method GET -Headers $authToken) -split "\n" | ? {($_ -notlike ".file-segments*") -and ($_ -notlike $null)}
            foreach ($file in $Filelist)
            {
                if(Test-Path ($FullPath, $($file -replace '/','\') -join '\'))
                {
                    $file = Get-ChildItem $($FullPath, $($file -replace '/','\') -join '\')
                    if($file.Length -lt 5GB)
                    {
                        $FileHash = (Get-FileHash $file.FullName -Algorithm MD5).hash.tolower()
                        $ETag = (Invoke-WebRequest -Uri $($api,$Container,$($file.FullName.TrimStart($FilePath) -replace '\\','/') -join '/') -Method Head -Headers $authToken).Headers.ETag
                        if(!($ETag -match $FileHash))
                        {
                            $file | Remove-Item -Force -ErrorAction SilentlyContinue
                            (Invoke-WebRequest -Uri $($api + "/$Container/$($file.FullName.TrimStart($FilePath) -replace '\\','/')") -Method GET -Headers $authToken -OutFile $($file.FullName))
                        }
                    }
                    else{Write-Verbose "File $($file.BaseName) Larger than 5GB. Not seeking Hash-match for $($file.FullName)"}
                }else{
                    Write-Verbose "File $FileName is missing. Downloading this file."
                    (Invoke-WebRequest -Uri $($api + "/$Container/$file") -Method GET -Headers $authToken -OutFile $($FullPath, $($file -replace '/','\' -replace ':','_') -join '\'))
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

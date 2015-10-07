#Function authenticates with Identity API and grabs initial catalog
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
#Function uses provided catalog to build API authentication token for header.
Function Get-Authtoken
{
    Param
    ([Parameter(Mandatory)]$catalog)
    $authToken = @{"X-Auth-Token"=$catalog.access.token.id}
    Return $authToken
}
#Function grabs current CloudFiles API uri for specified region.
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
    
    #Section defines presets for Filename, path, grabs API info required, and tests existance of the filepath location specified.
    #In verbose mode, outputs the preset parameters used.
    if($FileName -match '/'){$FileName = $FileName -replace '/','\'}
    $catalog = Get-Catalog -identityURI $identityURI -Credential $Credential
    $authToken = Get-Authtoken -catalog $catalog
    $api = Get-API -catalog $catalog -region $region
    
    if($FileName -ne $null){$FullPath = ($FilePath, $FileName -join '\')}else{$FullPath = $FilePath}
    if(Test-Path($FullPath)){$Exist = $true}else{$Exist = $false}
    Write-Verbose $PSBoundParameters
    $noHash = $false

    #Note: Hashmatching works for files under 5GB only.
    #Verify expected status, path exists and whether to matchsource.
    if(($Ensure -eq "Present") -and ($Exist -eq $true) -and ($MatchSource -eq $true))
    {
        Write-Verbose "Ensure is Present. FilePath exists. Testing MatchSource."
        if($SyncMode -eq "File")
        {
            #File test for a single configured file.
            if(Test-Path -Path $FullPath)
            {
                #Get a copy of the CloudFiles headers, especially the ETag value (MD5 checksum)
                $fileheader = (Invoke-WebRequest -Uri $($api + "/$Container/$($file -replace '\\','/')") -Method HEAD -Headers $authToken).Headers
                $fileinfo = Get-ChildItem $FullPath
                Write-Verbose "SyncMode: $SyncMode File check: $($fileinfo.BaseName)"
                #Test content to see whether file is greater than 5GB locally or on CloudFiles
                if(($fileheader.'Content-Length' -lt 5GB) -and ($fileinfo.Length -lt 5GB))
                {
                    #calculate MD5 hash for local file, compare to Cloudfiles hash. Return status of the hashmatch
                    $FileHash = (Get-FileHash $fileinfo.FullName -Algorithm MD5).hash.tolower()
                    $Hashmatch = $fileheader.ETag -match $FileHash
                    Write-Verbose "`n`tFileHash: $Filehash `n`tEtag: $($fileheader.ETag) `n`tHashmatch: $Hashmatch `n"
                }else{
                    #If a file is larger than 5GB, set the noHash value to reference that a file exceeded the match.
                    Write-Verbose "The file $FileName is too large. Recommend Setting MatchSource to false for this file."
                    $noHash = $true
                }
            }
        }
        else
        {
            #File test for a container with numerous files.
            #note: does not currently allow a 'wildcard' reference using file parameter.
            $Filelist = (Invoke-RestMethod -Uri $($api + "/$Container") -Method GET -Headers $authToken) -split "\n" | ? {($_ -notlike ".file-segments*") -and ($_ -notlike $null)}
            foreach ($file in $Filelist)
            {
                #For each listed item(file/folder), Grab the fileheader details.
                $fileheader = (Invoke-WebRequest -Uri $($api + "/$Container/$($file -replace '\\','/')") -Method HEAD -Headers $authToken).Headers
                Write-Verbose "SyncMode: $SyncMode. File to check: $file"
                #Test whether item referenced is a sudo-directory in the API and exists on the filesystem
                if(($fileheader.'Content-Type' -match "directory") -and (Test-Path ($FullPath, $($file -replace '/','\') -join '\')) -and ((Get-Item ($FullPath, $($file -replace '/','\') -join '\')).Attributes -match "Directory"))
                    {Write-Verbose "Directory Path confirmed: $($FullPath, $($file -replace '/','\') -join '\') `n"}
                #If not a directory and file exists, begin testing for file.
                elseif(($fileheader.'Content-Type' -notmatch "directory") -and (Test-Path -Path ($FullPath, $($file -replace '/','\') -join '\')))
                {
                    #Get File Info
                    $fileinfo = Get-ChildItem ($FullPath, $($file -replace '/','\') -join '\')
                    Write-Verbose "Hash check for local file: $($fileinfo.BaseName) `n"
                    if(($fileheader.'Content-Length' -lt 5GB) -and ($fileinfo.Length -lt 5GB))
                    {
                        #calculate MD5 hash for local file, compare to Cloudfiles hash. Return status of the hashmatch
                        $FileHash = (Get-FileHash $fileinfo.FullName -Algorithm MD5).hash.tolower()
                        $CheckHash = $fileheader.ETag -match $FileHash
                        if($Hashmatch -ne $false){$Hashmatch = $CheckHash}
                        Write-Verbose "`n`tFileHash: $Filehash `n`tEtag: $($fileheader.ETag) `n`tHashmatch: $CheckHash `n"
                    }
                    else
                    {
                        #File or Cloud Files header for file was greater than 5GB
                        Write-Verbose "The File $($fileinfo.BaseName) is larger than 5GB and will not be matched to source."
                        $noHash = $true
                    }
                }else{
                    #File doesn't exist locally. Return false so we can grab the file.
                    Write-Verbose "Content Missing: $file"
                    $Hashmatch = $false
                }
            }
            Write-Verbose "Filecheck Complete. Hashmatch: $Hashmatch NoHash: $noHash"
        }
        if($noHash -eq $null)
        {
            #Catchall for if processing occurs but somehow the noHash reference variable is deleted.
            $SyncStatus = $Hashmatch
        }
        elseif(($noHash -eq $true) -and ($SyncMode -eq "File"))
        {
            #A file over 5GB was specified, the file exists and was the only file being checked.
            Write-Verbose "File too large and SyncMode is File"
            $SyncStatus = $true
        }elseif($SyncMode -eq "File"){
            #A file was specified, and was tested for hash. Result is specified in the SyncStatus variable.
            Write-Verbose "Hashmatch completed and SyncMode is File"
            $SyncStatus = $Hashmatch
        }elseif(($noHash -eq $true) -and ($SyncMode -eq "Directory"))
        {
            #A directory was specified, and at least 1 file was over 5GB.
            #We still set SyncStatus based on whether all other files were successfully synced.
            #To replace this file, must manually remove the file, then allow resync to occur.
            Write-Verbose "File or Files greater than 5GB found and SyncMode is Directory"
            $SyncStatus = $Hashmatch
        }else{
            #Catchall represents directory checks where a file larger than 5GB was not discovered.
            Write-Verbose "Hashmatch completed and SyncMode is Directory"
            $SyncStatus = $Hashmatch
        }
    }
    #For a directory, if MatchSource is not set to true, check to ensure all files exist.
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
    #Set SyncStatus if a single file is specified and present. MatchSource is not true.
    elseif(($Ensure -eq "Present") -and ($FileName -ne $null) -and ($Exist -eq $true))
        {$SyncStatus = $true}
    #Test SyncStatus for a directory intended to be removed. (test is exclusive to files present in the container.)
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
    #If the Exist test returned true for a file, and Ensure is set to absent, set SyncStatus false.
    elseif(($Ensure -eq "Absent") -and ($Exist -eq $true))
        {$SyncStatus = $false}
    #If the Exist test returned false for a file, and Ensure is set to absent, set SyncStatus true.
    elseif($Ensure -eq "Absent")
        {$SyncStatus = $true}
    #Catchall Syncstatus. Should not be tripped unless a configuration error exists.
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

    #Section defines presets for Filename, path, grabs API info required, and tests existance of the filepath location specified.
    #In verbose mode, outputs the preset parameters used.
    if($FileName -match '/'){$FileName = $FileName -replace '/','\'}
    $catalog = Get-Catalog -identityURI $identityURI -Credential $Credential
    $authToken = Get-Authtoken -catalog $catalog
    $api = Get-API -catalog $catalog -region $region
    
    if($FileName -ne $null){$FullPath = ($FilePath, $FileName -join '\')}else{$FullPath = $FilePath}
    if(Test-Path($FullPath)){$Exist = $true}else{$Exist = $false}
    Write-Verbose $PSBoundParameters

    #Note: Current configuration and restrictions block syncing of segmented files at this time.
    if($Ensure -eq "Present")
    {
        #Section: for syncing of a single file in container.
        if($SyncMode -eq "File")
        {
            #If Item Exists, Remove it.
            Get-ChildItem -Path $FullPath -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            #Download item from Cloud Files
            (Invoke-WebRequest -Uri $($api + "/$Container/$($file -replace '\\','/')") -Method GET -Headers $authToken -OutFile $($FullPath))
        }
        #For syncing of an entire CloudFiles container. (excludes direct downloading of file-segments)
        else
        {
            #Create the FilePath directory if it does not already exist.
            if(!(Test-Path $FilePath)){New-Item -ItemType Directory -Path $FilePath}
            #Grab a list of items (Files/Folders) from the Cloud Files container.
            $Filelist = (Invoke-RestMethod -Uri $($api + "/$Container") -Method GET -Headers $authToken) -split "\n" | ? {($_ -notlike ".file-segments*") -and ($_ -notlike $null)}
            foreach ($file in $Filelist)
            {
                #Grab file headers for current item.
                $fileheader = (Invoke-WebRequest -Uri $($api + "/$Container/$($file -replace '\\','/')") -Method HEAD -Headers $authToken).Headers
                #Verify whether file is a folder or a file.
                if($fileheader.'Content-Type' -match "directory")
                {
                    Try
                    {
                        #Test to ensure the directory IS a directory locally. create it if missing.
                        if((Test-Path ($FullPath, $($file -replace '/','\') -join '\')) -and ((Get-Item ($FullPath, $($file -replace '/','\') -join '\')).Attributes -match "Directory"))
                        {Write-Verbose "Directory Path Already created"}
                        else{
                        Write-Verbose "Directory Path Missing: $($FullPath, $($file -replace '/','\') -join '\')"
                        New-Item -ItemType Directory -Path ($FullPath, $($file -replace '/','\') -join '\') -Force
                        }
                    }
                    Catch
                    {
                        #Solving for a file where a folder should be. Removes the file, then creates the folder
                        #WARNING: This is a destructive process. Be aware that this could remove a file created in the folder.
                        Write-Verbose "Invalid File Found. Removing and replacing file."
                        Get-Item -Path ($FullPath, $($file -replace '/','\') -join '\') | Remove-Item -Force
                        New-Item -ItemType Directory -Path ($FullPath, $($file -replace '/','\') -join '\') -Force
                    }Finally{
                        #Verifies the above attempts completed by responding on successful directory creation/existence.
                        if((Get-Item ($FullPath, $($file -replace '/','\') -join '\')).Attributes -match "Directory")
                            {Write-Verbose "Directory Successfully Created: $($FullPath, $($file -replace '/','\') -join '\'))"}
                    }
                }
                #For a non-directory File in Cloud Files container where the file exists locally.
                elseif(($fileheader.'Content-Type' -notmatch "directory") -and (Test-Path ($FullPath, $($file -replace '/','\') -join '\')))
                {
                    #Get the file information, test for size smaller than 5GB
                    $fileinfo = Get-ChildItem $($FullPath, $($file -replace '/','\') -join '\')
                    if(($fileheader.'Content-Length' -lt 5GB) -and ($fileinfo.Length -lt 5GB))
                    {
                        #Calculate the MD5 filehash for the file in question.
                        $FileHash = (Get-FileHash $fileinfo.FullName -Algorithm MD5).hash.tolower()
                        if(!($fileheader.ETag -match $FileHash))
                        {
                            #If the file doesn't match, Remove it and re-download.
                            $fileinfo | Remove-Item -Force -ErrorAction SilentlyContinue
                            (Invoke-WebRequest -Uri $($api + "/$Container/$($file -replace '\\','/')") -Method GET -Headers $authToken -OutFile $($fileinfo.FullName))
                        }
                    }
                    #In the event file exists & is larger than 5GB, Remark on the file in Verbose-mode.
                    else{Write-Verbose "File $($fileinfo.BaseName) exists and is larger than 5GB. Not seeking Hash-match for $($file.FullName)"}
                }else{
                    #file not found. Download it.
                    Write-Verbose "File $File is missing. Downloading this file."
                    (Invoke-WebRequest -Uri $($api + "/$Container/$($file -replace '\\','/')") -Method GET -Headers $authToken -OutFile $($FullPath, $($file -replace '/','\') -join '\'))
                }
            }
        }
    }
    #If Ensure is absent and the filepath exists, remove all contents in the path.
    #For File, this is exclusive to the file.
    #For Directory, this will remove all contents from the base folder. (Comments if a case should be made for unique file removal.)
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
    #Use Get-TargetResource to test configuration. Evaluate result as test.
    $Status = Get-TargetResource @PSBoundParameters
    if($Status.Ensure -ne $true){Return $False}
    else{Return $true}
}



Export-ModuleMember -Function *-TargetResource

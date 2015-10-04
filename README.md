rsBlobStorage
=====

This module contains tools for retreiving files/content from Cloud File storage containers as part of DSC.

```PoSh
rsGetCloudFiles Packages
{
	Container = "Packages"
	Region = "DFW"
	Credential = $Credentials.User1
	SyncMode = "Directory"
	FilePath = "C:\DevOps\Packages"
	FileName = $null
	MatchSource = $True
	Ensure = "Present"
}
```

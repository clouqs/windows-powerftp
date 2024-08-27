# Install IIS Feature
Install-WindowsFeature -Name Web-Server -IncludeManagementTools

# Install FTP feature
Install-WindowsFeature -Name Web-Ftp-Server -IncludeAllSubFeature -IncludeManagementTools -Verbose

# Creating new FTP site
$SiteName = "Demo FTP Site"
$RootFolderpath = "C:\DemoFTPRoot"
$PortNumber = 21
$FTPUserGroupName = "Demo FTP Users Group"
$FTPUserName = "FtpUser"
$FTPPassword = ConvertTo-SecureString "p@ssw0rd" -AsPlainText -Force

if (!(Test-Path $RootFolderpath)) {
    # if the folder doesn't exist
    New-Item -Path $RootFolderpath -ItemType Directory # create the folder
}

# Ensure the IIS:\ drive is available
Import-Module WebAdministration

# Create the FTP Site
New-WebFtpSite -Name $SiteName -PhysicalPath $RootFolderpath -Port $PortNumber

# Creating the local Windows group
if (!(Get-LocalGroup $FTPUserGroupName -ErrorAction SilentlyContinue)) {
    # if the group doesn't exist
    New-LocalGroup -Name $FTPUserGroupName `
        -Description "Members of this group can connect to FTP server" # create the group
}

# Creating an FTP user
If (!(Get-LocalUser $FTPUserName -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $FTPUserName -Password $FTPPassword `
        -Description "User account to access FTP server" `
        -UserMayNotChangePassword
} 

# Add the created FTP user to the group Demo FTP Users Group
Add-LocalGroupMember -Name $FTPUserGroupName -Member $FTPUserName -ErrorAction SilentlyContinue

# Enabling basic authentication on the FTP site
$param = @{
    Path    = "IIS:\Sites\$SiteName"
    Name    = 'ftpserver.security.authentication.basicauthentication.enabled'
    Value   = $true 
}
Set-ItemProperty @param

# Adding authorization rule to allow FTP users 
# in the FTP group to access the FTP site
$param = @{
    PSPath   = 'IIS:\'
    Location = $SiteName 
    Filter   = '/system.ftpServer/security/authorization'
    Value    = @{ accessType = 'Allow'; roles = $FTPUserGroupName; permissions = 1 } 
}

Add-WebConfiguration @param

# Changing SSL policy of the FTP site
'ftpServer.security.ssl.controlChannelPolicy', 'ftpServer.security.ssl.dataChannelPolicy' | 
ForEach-Object {
    Set-ItemProperty -Path "IIS:\Sites\$SiteName" -Name $_ -Value 0
}

$ACLObject = Get-Acl -Path $RootFolderpath
$ACLObject.SetAccessRule(
    ( # Access rule object
        New-Object System.Security.AccessControl.FileSystemAccessRule(
            $FTPUserGroupName,
            'ReadAndExecute',
            'ContainerInherit,ObjectInherit',
            'None',
            'Allow'
        )
    )
)
Set-Acl -Path $RootFolderpath -AclObject $ACLObject

# Checking the NTFS permissions on the FTP root folder
Get-Acl -Path $RootFolderpath | ForEach-Object Access

# Test FTP Port and FTP access
Test-NetConnection -ComputerName localhost -Port 21

# Note: The command 'ftp localhost' should be run manually in a command prompt or PowerShell terminal to test FTP connectivity.

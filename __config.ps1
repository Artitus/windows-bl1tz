<#
    This configuration file is used to setup all the options necessary for each module in this script. Please read each option carefully and set the options necessary for the
    image you are working with.
#>

#Dont touch this! Makes powershell do the best it can instead of just quitting on errors. Makes the script much more resiliant to errors.
$ErrorActionPreference = 'Continue'

# List of programs that are automatically removed by the script
[string[]] $global:BadPrograms = [string[]]@( "nc.exe", 
    "*netcat*", "rvlkl.exe", "run.vbs", "john.exe", 
    "sys32.exe", "rootkit.exe", "mytrojan.exe", "BitComet", 
    "SpeedBit", "helium9", "Nexus Radio", "TVexe TV HD", 
    "Itunes", "Bittorrent", "qbittorrent", "Quicktime");

#A list of packages to install with choco. Remove the '#' to install the package, or add your own if you wish. Add a '#' before a package to remove it from the install list
$global:RequiredPrograms = @(
    "firefox",
    "malwarebytes",
    "mbsa",
    "microsoftsecurityessentials",
    #"opera",
    #"bitnami-xampp",
    #"adobereader",
    "javaruntime",
    #"python",
    "notepadplusplus",
    "everything",
    #"ccleaner",
    #"custom program here",
    #"custom program here",
    #"custom program here",
    #"custom program here",
    #"custom program here",
    #"custom program here",
    #"custom program here",
    #"custom program here",
    #"custom program here",
    #"custom program here",
    #"custom program here",
    #"custom program here",
    #"custom program here",
    #"custom program here",
    #"custom program here",
    #"custom program here",
    #"custom program here",
    #"custom program here",
    "ie11"
);

function Set-UserOptions
{
    #Default password for all users that do not have a password override
    $global:UserCommonPassword = "Bl!tz3dUs3r-2020"; 

    #Should the script clear the user's home directories
    $global:ClearHomeDirectories = $True; 

    #Should the script clear the user's appdata
    $global:ClearAppData = $True; 

    #Should the script automatically disable/delete user accounts
    $global:AutoManageUserAccounts = $False; 

    #Should the script delete the user's profile in addition to disabling it.
    $global:DeleteFullProfiles = $False; 

    #All users that are allowed to exist on the system
    $global:AllowedStandardUsers = 
    @(

    ); #Example Entry: myuser,

    #All administrators that are allowed to exist on the system and their respective passwords
    $global:AllowedAdmins = 
    @{

    }; #Example Entry: MyAdmin = "MyPassword";
}

function Set-CriticalServices
{
    #Enable Active Directory
    $global:ActiveDirectory = $False;

    #Enable SMB. Please note that if ANY SHARED FOLDERS ARE REQUIRED this MUST be $True
    $global:__SMB__ = $False;

    #Enable Remote Desktop
    $global:__RDP__ = $False;

    #Enable IIS Web Server.
    $global:__IISWS__ = $False;

    #Enable FTP server (only if microsoft IIS FTP, not filezilla)
    $global:__FTP__ = $False;

    #Enable DNS Server. NOTE: if active directory is in use, set this to $true.
    $global:__DNS__ = $False;

    #Enable xampp server (web server). Only if in readme.
    $global:__XAMPP__ = $False;

    #Critical service settings

    #SMB
    #Anonymous shares for SMB
    $global:SMB_AnonymousSharesList = "";
    #End of SMB

    #RDP
    $global:RDP_Port = 31337;
    #End of RDP

    #Dont edit these settings
    $global:__UsesIIS__ = $global:__IIS__ -or $global:__FTP__;
    $global:__UsesDNS__ = $global:__DNS__ -or $global:ActiveDirectory;
}

#Misc Settings

#Allow Internet Explorer
$global:IE_Enabled = $True;

#Set to either win10 or win16
$global:ScriptPlatform = "win10";

#Set to $True when this script is configured completely.
$global:ScriptConfigured = $False;

<#
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
    END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION::END OF CONFIGURATION
#>

#DEFAULT SCRIPT ENVIRONMENT. DO NOT EDIT ANYTHING PAST HERE!
$global:UserCommonPassword = "Bl!tz3dUs3r-2020";
$global:CurrentUser = $env:USERNAME;
$global:ClearHomeDirectories = $True; 
$global:ClearAppData = $True; 
$global:AutoManageUserAccounts = $False; 
$global:DeleteFullProfiles = $False; 
$global:AllowedStandardUsers = @();
$global:AllowedAdmins = @{ };
$global:ActiveDirectory = $False;
$global:__SMB__ = $False;
$global:__RDP__ = $False;
$global:__IISWS__ = $False;
$global:__FTP__ = $False;
$global:__DNS__ = $False;
$global:__UsesDNS__ = $False;
$global:SMB_AnonymousSharesList = "";
$global:RDP_Port = 31337;
$global:__UsesIIS__ = $False;
$global:__XAMPP__ = $False;

#This is a configuration sequence only. None of these modules should be disabled
Set-UserOptions;
Set-CriticalServices;
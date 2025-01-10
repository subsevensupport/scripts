# Get the ID and security principal of the current user account
$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)

# Get the security principal for the Administrator role
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

# Check to see if we are currently running "as Administrator"
if ($myWindowsPrincipal.IsInRole($adminRole)) {
    # We are running "as Administrator" - so change the title and background color to indicate this
    $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
    $Host.UI.RawUI.BackgroundColor = "DarkBlue"
    clear-host
}
else {
    # We are not running "as Administrator" - so relaunch as administrator

    # Create a new process object that starts PowerShell
    $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";

    # Specify the current script path and name as a parameter
    $newProcess.Arguments = $myInvocation.MyCommand.Definition;

    # Indicate that the process should be elevated
    $newProcess.Verb = "runas";

    # Start the new process
    [System.Diagnostics.Process]::Start($newProcess);

    # Exit from the current, unelevated, process
    exit
}


cd 'C:\Program Files (x86)\BleachBit'
$Output = .\bleachbit_console.exe -c adobe_reader.cache adobe_reader.tmp brave.cache brave.vacuum chromium.cache chromium.vacuum discord.cache discord.vacuum firefox.cache firefox.vacuum flash.cache gimp.tmp google_chrome.cache google_chrome.vacuum google_earth.temporary_files gpodder.cache gpodder.vacuum internet_explorer.cache java.cache microsoft_edge.cache microsoft_edge.vacuum openofficeorg.cache opera.cache opera.vacuum safari.cache safari.vacuum seamonkey.cache secondlife_viewer.Cache silverlight.temp slack.cache slack.vacuum smartftp.cache system.recycle_bin system.tmp system.updates thunderbird.cache thunderbird.vacuum vuze.cache vuze.temp waterfox.cache waterfox.vacuum windows_media_player.cache winrar.temp yahoo_messenger.cache zoom.cache
$DiskSpaceRecovered = $Output | Select-String -Pattern "recovered:"
# Ninja-Property-Set -Name "bleachbit" -Value $DiskSpaceRecovered
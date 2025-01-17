# Apps are separated into 3 categories: Bloat, Marginal, and Core
# Remove each group using its parameter, e.g. -Bloat
# Or use -All to remove all App Packages except the Core ones

param (
    [switch]$Bloat = $false,
    [switch]$Marginal = $false,
    [switch]$Core = $false,
    [switch]$All = $false
)

$MsftBloat = @(
    "*3DBuilder*"
    "*3DViewer*"
    "Microsoft.Advertising.Xaml" # too much?
    "*BingFinance*"
    "*BingNews*"
    "*BingSports*"
    "*BingTranslator*"
    "*BingWeather*"
    "*Copilot*"
    "*FreshPaint*"
    "*3DViewer*"
    "*FeedbackHub*"
    "*MixedReality.Portal*"
    "*NetworkSpeedTest*"
    "*People*"
    "*Print3D*"
    "*Wallet*"
    "*windowscommunicationsapps*"
    "*WindowsMaps*"
    "*WindowsPhone*"
    "*YourPhone*"
    "*Zune*"
    "*CommsPhone*"
    "*ConnectivityStore*"
    "*GetHelp*"
    "*Getstarted*"
    "*Messaging*"
    "*OneConnect*"
    "*Microsoft3DViewer*"
    "*BingFoodAndDrink*"
    "*BingHealthAndFitness*"
    "*BingTravel*"
    "*WindowsReadingList*"
)

$MsftUtilities = @(
    "*MicrosoftStickyNotes*"
    "*WindowsSoundRecorder*"
    "*ScreenSketch*"
    "*PowerBI*"
    "*Skype*"
)

$MsftCore = @(
    "*Photos*"
    "*Alarms*"
    "*Calculator*"
    "*Camera*"
    "*Paint*"
    "*Store*"
    "*Edge*"
)

$MsftGaming = @(
    "*GamingServices*"
    "*Solitaire*"
    "*Minecraft*"
    "*Xbox*"
    "*GamingApp*"
)

$MsftOffice = @(
    "*OfficeHub*"
    "*OneNote*"
    "*Office.Sway*"
)

$NonMsftBloat = @(
    "*PicsArt*"
    "*EclipseManager*"
    "*Netflix*"
    "*PolarrPhotoEditorAcademicEdition*"
    "*Wunderlist*"
    "*LinkedIn*"
    "*AutodeskSketchBook*"
    "*Twitter*"
    "*Disney*"
    "*MarchofEmpires*"
    "*ActiproSoftwareLLC*"
    "*iHeartRadio*"
    "*FarmVille*"
    "*Duolingo*"
    "*CyberLink*"
    "*DolbyAccess*"
    "*Drawboard*"
    "*Facebook*"
    "*Fitbit*"
    "*Flipboard*"
    "*GAMELOFT*"
    "*NORDCURRENT*"
    "*Pandora*"
    "*Playtika*"
    "*Casino*"
    "*Shazam*"
    "*SlingTV*"
    "*TheNewYorkTimes*"
    "ThumbmunkeysLtd.PhototasticCollage"
    "*TuneInRadio*"
    "*WinZip*"
    "XINGAG.XING"
    "*flaregames*"
    "*king.com*"
    "*Amazon*"
    "*TikTok*"
)

$NonMsftMarginal = @(
    "*Plex*"
    "*Spotify*"
    "*McAfee*"
    "*Adobe*" #
)

$NonMsftCore = @(
    "*Keeper*"
)

$apps = @()
$BloatApps = $NonMsftBloat + $MsftBloat + $MsftGaming
$MarginalApps = $MsftUtilities + $NonMsftMarginal
$CoreApps = $MsftCore + $MsftOffice + $NonMsftCore

if ($Bloat) { $apps += $BloatApps }
if ($Marginal) { $apps += $MarginalApps }
if ($Core) { $apps += $CoreApps }


if ($All) {
    Write-Host "Removing all apps except Microsoft Core"
    $packages = Get-AppxPackage -AllUsers
    foreach ($app in $MsftCore) {
        $packages = $packages | Where-Object { $_.Name -notlike $app }
    }
    $packages | Remove-AppxPackage -AllUsers

    $packages = Get-AppxProvisionedPackage -online
    foreach ($app in $MsftCore) {
        $packages = $packages | Where-Object { $_.DisplayName -notlike $app }
    }
    $packages | Remove-AppxProvisionedPackage -online
}
else {
    foreach ($app in $apps) {
        Write-Output "Trying to remove $app"
    
        Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers
    
        Get-AppXProvisionedPackage -Online |
        Where-Object DisplayName -EQ $app |
        Remove-AppxProvisionedPackage -Online
    }
}

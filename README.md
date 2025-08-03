# Windows Administration PowerShell Scripts

This repository contains a collection of PowerShell scripts designed for Windows system administration, optimization, and cleanup. These scripts are suitable for deployment and management through a Remote Monitoring and Management (RMM) platform like NinjaOne.

-----

## 📜 License

This project is licensed under the **GNU General Public License v3.0**. Please see the [LICENSE](https://www.google.com/search?q=LICENSE) file for full details.

-----

## 🚀 Scripts

The scripts are categorized into two main groups: System Configuration and System Cleanup/Optimization.

### System Configuration

These scripts help configure and manage various Windows settings.

  * **`NamePC.ps1`**: A comprehensive script that automatically renames a computer based on a standardized naming convention: `CLIENT-TYPE-ASSET`.

      * It fetches a **client code** and **primary server role** from NinjaOne custom fields.
      * It determines the **computer type** (e.g., Physical Server, Virtual Server, Laptop, Desktop) by querying WMI/CIM for the chassis type.
      * It retrieves a unique **asset tag** from a central API and saves it back to a NinjaOne custom field.
      * Requires an `.env` file with API credentials for asset tag generation.

  * **`disable_hibernate.ps1`**: Turns off the hibernate feature using `powercfg.exe /hibernate off`.

  * **`disable_sleep.ps1`**: Prevents the system from going into standby or turning off the disk when plugged in by setting AC power configuration timeouts to zero.

  * **`speedtest.ps1`**: Performs an internet speed test by downloading and running the Ookla Speedtest CLI. It records download/upload speeds, latency, jitter, and packet loss, then saves the results to a custom field in NinjaOne.

  * **`.gitignore`**: A standard gitignore file for ignoring environment variables, local configuration overrides, and temporary files.

### System Cleanup and Optimization

These scripts are for cleaning up unnecessary files, removing bloatware, and optimizing the system.

  * **`windows_debloat.ps1`**: A powerful and highly customizable script for debloating Windows and enhancing privacy. It can:

      * Disable telemetry, location tracking, Cortana, and other privacy-related settings.
      * Tweak services, UAC, and firewall settings.
      * Adjust the user interface by hiding the search box, removing Start Menu tiles, and showing file extensions.
      * Uninstall a wide range of default and pre-installed Microsoft and third-party applications.

  * **`debloat.ps1`**: A script focused specifically on removing pre-provisioned and installed AppX packages from Windows. Apps are categorized into **Bloat**, **Marginal**, and **Core** groups, allowing for targeted removal. It can also remove everything except for core Microsoft apps.

  * **`cleanmgr.ps1`**: Automates the Windows Disk Cleanup utility (`cleanmgr.exe`). It modifies registry keys to pre-select all cleanup options (like temporary files, recycle bin, and update cleanup) and then runs the tool silently.

  * **`bleachbit.ps1` / `drive_cleanup.ps1`**: These scripts automate the cleaning process using the BleachBit console application. They clear the cache and temporary files for numerous applications, including web browsers (Chrome, Firefox, Edge), communication tools (Discord, Slack), and system temp folders.

  * **`patchcleaner.ps1`**: An automation script for **PatchCleaner**, a tool that finds and removes orphaned Windows Installer (`.msi`/`.msp`) files from the `C:\Windows\Installer` directory. The script can be set to either move or delete the orphaned files.
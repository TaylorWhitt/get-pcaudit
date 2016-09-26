 Function Get-PCAudit{
[CmdletBinding()] 
 Param(
  [Parameter(Mandatory=$False,Position=0, ValueFromPipeline=$True, ValueFromPipelineByPropertyName = $true)]
  [Microsoft.ActiveDirectory.Management.ADComputer[]]$computer
)

BEGIN {
Import-Module .\get-lastloggedonuser.psm1
Import-Module ActiveDirectory
}

PROCESS {
$computerName = $computer.DNSHostName

#reservations=Get-DhcpServerv4Reservation -ScopeId "192.2.163.0"

Write-Verbose "Checking $computerName"
if(Test-Connection -TimeToLive 1 -Count 1 -ErrorAction SilentlyContinue -computername $computerName){

    #test to see if the hostname matches otherwise we might have stale dns entry
    if($computerName.split('.')[0].ToUpper() -eq ((Get-WmiObject -Class Win32_ComputerSystem -ComputerName $computerName).Name).toUpper()){
        Write-Verbose "Scanning $computerName"
        $wmiProcObj = Get-WmiObject -ComputerName $computerName Win32_Processor -ErrorAction SilentlyContinue
        $compSerialNumer =(Get-WmiObject -ComputerName $computerName Win32_Bios).SerialNumber
        if($wmiProcObj.length -lt 1){

        $processorSpeed = $wmiProcObj.MaxClockSpeed.ToString()
        if ($wmiProcObj.Name -eq "Intel Pentium III Xeon processor"){
            $wmiProcName = "Intel(R) Core 2 Duo(TM)"
        }
        else{

        $wmiProcName = $wmiProcObj.Name.ToString()
        }
        }
        else{

        $processorSpeed = $wmiProcObj[0].MaxClockSpeed.ToString()
        if ($wmiProcObj[0].Name -eq "Intel Pentium III Xeon processor"){
            $wmiProcName = "Intel(R) Core 2 Duo(TM)"
        }
        else{
        $wmiProcName = $wmiProcObj[0].Name.ToString()
        }

        }
        $lastLogonUser = (get-lastlogon $_.DnsHostName).User

        $compOS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $computerName

        $compOSVersion = $compOS.Version


        $compOSCaption = $compOS.Caption

        $compOSServicePack = $compOS.ServicePackMajorVersion

        $compOSArch = $compOS.OSArchitecture
        if ($compOSArch -eq $null){
            $compOSArch = "32-bit"
        }


        $wmiMemObj = Get-WmiObject -ComputerName $computerName Win32_ComputerSystem -ErrorAction SilentlyContinue

        $memory = $wmiMemObj.TotalPhysicalMemory
        $memoryMB = $memory  / 1024 / 1024

        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $computerName)
        $ip = [System.Net.Dns]::GetHostAddresses($_.DnsHostName) | Where-Object -Property AddressFamily -eq InterNetwork
        $ip = $ip[0].IPAddressToString
        $dhcpReservations | % {
            if ($_.IPAddress.IPAddressToString -eq $ip){$ip+=" (Reserved)"}
        }


        $wmiProd = Get-WmiObject -Class Win32_product -ComputerName $computerName
        #$software = $wmiProd | Select-Object Name
            $comp = @{
    'Computer Name' = $_.DnsHostName
    'Serial Number' = $compSerialNumer
    'Last logged on user' = $lastLogonUser
    'Operating System' = $compOSCaption
    'Operating System Version' = $compOSVersion
    'Arch' = $compOSArch
    'Service Pack Level' = $compOSServicePack
    'IP Address' = $ip
    'CPU Name' = $wmiProcName
    'CPU Speed(Ghz)' = $processorSpeed
    'Memory(MB)' = $memoryMB
    'Software' = $software
    }

$outComp = new-object -TypeName PSObject -Property $comp

write-output $outComp
        
    } #/if wmic name matches $_.DnsHostName
else{
    Write-host -ForegroundColor Red "WMIC Name does not match, possible bad dns entry"
}
}
else{
    Write-Warning "$computerName not responding to pings"
}


}
}
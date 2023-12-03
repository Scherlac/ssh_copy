# This is a powershell script to copy the ssh key to a remote host
#
# **Note**: Not all part of the script are tested, use it at your own risk, please report any issue or suggestion
# **Note**: The script requires powershell 7.3 or higher (we use "?" operator (ternary operator) and "-like" operator)
# 
# The script will:
# - generate a new ssh key if it does not exist
# - copy the key to the remote host
# - update the config file with the host alias and key file
# - show the key file location
# - show a command example to connect to the remote host

function  Copy-SSHKey {
    param (
        [Parameter(Mandatory=$true)]
        [string]$RemoteHost,
        
        # port number
        [Parameter(Mandatory=$false)]
        [int]$Port = 22,
        
        # host alias
        # by default we use the remote host name without domain name as alias
        [Parameter(Mandatory=$false)]
        [string]$Alias = ($RemoteHost -replace '\..*',''),
        
        # remote user
        [Parameter(Mandatory=$true)]
        [string]$RemoteUser,

        # key file name, by default we use the user profile folder and the alias
        [Parameter(Mandatory=$false)]
        [string]$KeyFile = ("$env:USERPROFILE\.ssh\id_rsa_$( $Alias -replace '[^a-zA-Z0-9]','')"),

        # Key comment
        [Parameter(Mandatory=$false)]
        [string]$KeyComment = "$RemoteUser@$RemoteHost",

        # encription type
        [Parameter(Mandatory=$false)]
        [ValidateSet('rsa2048', 'rsa4096','ed25519')]
        [string]$KeyType = 'ed25519',

        # remote host operating system
        [Parameter(Mandatory=$false)]
        [ValidateSet('linux', 'windows')]
        [string]$RemoteOS = 'linux',

        # update method for the remote host authorized_keys file
        [Parameter(Mandatory=$false)]
        [ValidateSet('append', 'replace')]
        [string]$UpdateMethod = 'append',

        # specify this flag if the remote host is windows and the user is an administrator
        [switch]$AdminUser,

        # force to overwrite the key file even if it exists
        [switch]$ForceGenerate,

        # force to upload the key even if it exists
        [switch]$ForceUpload
    )


    # update the config file with the host alias and key file
    $configText = ( Get-Content -Raw "$env:USERPROFILE\.ssh\config" )
    $configText = $configText -replace "`r`n", "`n"


    # We replace the host alias if it exists with multiline regex
    #
    # SSH config fils description: https://linux.die.net/man/5/ssh_config
    #
    # NOTE: according to the documentation, the host alias section continues 
    # "up to the next Host keyword" but it does not work for the last host
    # alias. So we expect all options for the same host alias are indented 
    # with at least one space    
    $regex = @"
(?mx) # multiline, ignore pattern whitespace
(?<hostAlias>
(^[ \t]*Host\s+host4\s*$\n)
((^[ \t]+[^\n]*$\n)|(^\#[^\n]*$\n)|(^\s*$\n))+
)
"@

    # we create the new entry to append to the config file
    $newConfig = @"

Host $Alias
    HostName $RemoteHost
    Port $Port
    User $RemoteUser
    IdentityFile $KeyFile

"@

    If ($configText -match $regex) {
        Write-Host "Updating the config file..."
        $configText = $configText -replace $regex, ($newConfig + "`${End}")
    } else {
        Write-Host "Appending to the config file..."
        $configText += $newConfig
    }

    # remove multiple empty lines
    $configText = $configText -replace "`n{3,}", "`n`n"

    # show the config file for the user and ask for confirmation
    Write-Host "The following text will be appended to the config file"
    Write-Host $configText
    Write-Host "Press any key to continue or CTRL+C to cancel"
    $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

    $configText | Set-Content -NoNewline "$env:USERPROFILE\.ssh\config"

    if (-not (Test-Path $KeyFile) -or $ForceGenerate.IsPresent) {

        $type = $KeyType -like 'rsa*' ? 'rsa' : 'ed25519'
        $bits = $type -eq 'rsa' ? @( "-b", ($KeyType -replace 'rsa','') ) : $null

        Write-Host "Generating $type key..."
        Write-Host "When prompted, please, provide a passphrase to encrypt the key OR press enter to skip"
        
        # generate the key based on the selected type
        ssh-keygen -t $type $bits -f $KeyFile -C $KeyComment
        $newKey = $true
    }

    if ($newKey -or $ForceUpload.IsPresent) {
        # base on the remote OS we copy the key to the remote host
        if ($RemoteOS -eq 'linux') {
            Write-Host "Copying the key to the remote host..."

            # enable verbose mode if the trace flag is present
            if ($Trace.IsPresent) {
                $command += ( @"
set -v
"@  )
            }

            # remove all the keys with the same comment
            if ($UpdateMethod -eq 'replace') {
                $command += ( @"
grep '$KeyComment' ~/.ssh/authorized_keys >> ~/.ssh/authorized_keys.removed
grep -v '$KeyComment' ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.new
cat ~/.ssh/authorized_keys.new > ~/.ssh/authorized_keys
"@  )
            } 
            
            # append the key to the authorized_keys file
            $command += ( @"
cat <<EOF >> ~/.ssh/authorized_keys
$(Get-Content "$KeyFile.pub")
EOF
"@  )
            # -tt is needed to force the remote host to allocate a tty for the command (needed for cat <<EOF)
            ssh -tt $Alias $command
        } else {
            Write-Host "Copying the key to the remote host..."
            # ISSUE: https://unix.stackexchange.com/questions/709054/ssh-publickey-authentication-failure-receive-packet-type-51-sshd-is-not-accep
            # INFO: https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement#administrative-user
            if ($AdminUser.IsPresent) {
                $remoteKeyFile = "`${env:ProgramData}\ssh\administrators_authorized_keys"
            } else {
                $remoteKeyFile = "`${env:USERPROFILE}\.ssh\authorized_keys"
            }

            $command = ""

            # enable verbose mode if the trace flag is present
            if ($Trace.IsPresent) {
                $command += ( @"
Set-PSDebug -Trace 1
"@  )
            }

            # remove all the keys with the same comment if the update method is replace
            if ($UpdateMethod -eq 'replace') {
                $command += ( @"
`$authorizedKeys = "$remoteKeyFile"; 
`$content = (Get-Content -Raw "`$authorizedKeys"); 
`$content | where { `$_ -match '$KeyComment' } | Out-File -NoNewLine -Append -FilePath "`${authorizedKeys}.removed"; 
`$content | where { `$_ -notmatch '$KeyComment' } | Out-File -NoNewLine -FilePath "`${authorizedKeys}"; 
"@  )
            }

            $command = ( @"
'$(Get-Content "$KeyFile.pub")' | Out-File -NoNewLine -Append -FilePath "`${authorizedKeys}"
"@ )

            # we need to escape the double quotes and remove the new lines
            $command = $command -replace '"','""'
            $command = $command -replace '`n',' '

            $command = ( @"
powershell -Command "$()"
"@ )

            Write-Host $command
            ssh $Alias $command
        }
    }

    # show the key file location
    Write-Host "The key file is located at $KeyFile"

    # show a command example to connect to the remote host
    Write-Host "To connect to the remote host use the following command"
    Write-Host "ssh $Alias"


}



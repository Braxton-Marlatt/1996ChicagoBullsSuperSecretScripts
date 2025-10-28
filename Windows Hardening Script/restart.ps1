foreach ($computer in $computers) {
    Write-Host "Processing $computer..."
    try {
        Invoke-Command -ComputerName $computer -ScriptBlock {
            shutdown /r /t 0
        } 
        Write-Host "Reboot command sent to $computer"
    }
    catch {
        Write-Warning "Failed to process ${computer}: $($_.Exception.Message)"
    }
}

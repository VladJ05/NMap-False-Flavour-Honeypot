$folders = @(
    "responses",
    "resulted_datasets",
    "resulted_models"
)

foreach ($folder in $folders) {
    if (Test-Path $folder) {
        Get-ChildItem -Path $folder -File | Remove-Item -Force
    }
}

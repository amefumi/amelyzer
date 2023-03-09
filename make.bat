del main.exe.manifest
copy src\ui\main.manifest main.exe.manifest
go build -ldflags="-H windowsgui" src\main.go
.\main.exe
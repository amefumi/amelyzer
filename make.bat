del main.exe.manifest
del main.exe
copy src\ui\main.manifest main.exe.manifest
go mod download
go build src\main.go
.\main.exe
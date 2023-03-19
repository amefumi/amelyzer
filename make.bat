del build\Amelyzer.exe
go mod download
cd src
go build -ldflags="-H windowsgui"
move src.exe ..\build\Amelyzer.exe
cd ..
build\Amelyzer.exe
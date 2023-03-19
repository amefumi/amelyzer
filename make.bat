del build\Amelyzer.exe
assets\rsrc.exe -manifest assets\main.manifest -ico assets\app.ico -o rsrc.syso
move rsrc.syso src\rsrc.syso
go mod download
cd src
go build -ldflags="-H windowsgui"
move src.exe ..\build\Amelyzer.exe
cd ..
build\Amelyzer.exe
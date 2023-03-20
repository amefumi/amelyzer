del build\Amelyzer.exe
go mod download
cd src
echo go build -ldflags="-H windowsgui"
go build
move src.exe ..\build\Amelyzer.exe
cd ..
copy build\Amelyzer.exe Amelyzer.exe
Amelyzer.exe
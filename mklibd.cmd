cd %~dp0
cargo build
cd %GOPATH%\src\github.com\ethereumproject\go-ethereum\machine\sputnik\windows_amd64
del /q libsputnikvm.a
copy %~dp0target\debug\svmffi.lib libsputnikvm.a


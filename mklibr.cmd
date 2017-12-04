cd %~dp0
cargo build --release
cd %GOPATH%\src\github.com\ethereumproject\go-ethereum\machine\sputnik\windows_amd64
del /q libsputnikvm.a
copy %~dp0target\release\sputnikvm.lib libsputnikvm.a


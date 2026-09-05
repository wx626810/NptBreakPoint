@echo off
REM Build NpDrvInst.dll (MinGW) -> NpHvCtl-Tauri embeds it via include_bytes!
setlocal
set "GXX=C:\Users\PC\mingw64\bin\g++.exe"
if not exist "%GXX%" ( where g++ >nul 2>nul && (set "GXX=g++") )
if not exist "%GXX%" ( echo [ERROR] g++ not found & exit /b 1 )
set "ROOT=%~dp0.."
if not exist "%ROOT%\nphv-drv\bin" mkdir "%ROOT%\nphv-drv\bin"
"%GXX%" -O2 -DNPT_NO_EMBEDDED -shared -static -static-libgcc -static-libstdc++ -std=c++23 -I"%ROOT%\NptHook\include" -I"%ROOT%\NpHvCtl" -I"%ROOT%\NpHvCtl\sf" "%ROOT%\nphv-drv\drv_inst.cpp" "%ROOT%\NpHvCtl\CiPatch.cpp" -o "%ROOT%\nphv-drv\bin\NpDrvInst.dll" -ladvapi32 -lshell32 -lntdll -lwinpthread
if errorlevel 1 ( echo [ERROR] DLL build FAILED & exit /b 1 )
echo [OK] nphv-drv\bin\NpDrvInst.dll
endlocal

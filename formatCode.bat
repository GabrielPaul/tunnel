@echo off
set CUR_DIR=%cd%
:: set astyle path
set ASTYLE="D:\Program Files\AStyle\astyle-3.4.6-x64\AStyle.exe"
set FORMAT_FILE=*.c,*.h


:: echo %1
:: pause
if "%1"=="kr" (	:: k/r style
:: %AStyle% --style=kr -n -O -xj --recursive %CUR_DIR%\%FORMAT_FILE%
%AStyle% --style=kr -n -j --recursive %CUR_DIR%\%FORMAT_FILE%
:: %AStyle% --style=kr -n --recursive %CUR_DIR%\%FORMAT_FILE%
echo "Astyle format k/r style done!"
) else if "%1"=="otherTODO" (
%AStyle% --style=allman -k3 -W3 -t -xG -S -L -M120 -y -xf -j -xq  -xS -n -s4 --indent=spaces=4 --recursive %CUR_DIR%\%FORMAT_FILE%
) else (
%AStyle% --style=allman -k3 -W3 -t -xG -S -L -M120 -y -xf -j -xq  -xS -n -s4 --indent=spaces=4 -p -xV -U --recursive %CUR_DIR%\%FORMAT_FILE%
echo "Astyle format default style done!"
)


:: call :REVERSE_DIR %CUR_DIR%

:: :REVERSE_DIR
:: ::echo ***%1
:: if "%1" NEQ "" (
:: 	if "%1" NEQ ".git" (
:: 		for /f %%i in ('dir /b /ad "%1"') do (
:: 			echo %1\%%i
:: 			%AStyle% --style=allman -k3 -W3 -t -xG -S -L -M120 -y -xf -j -xq  -xS -n -s4 --indent=spaces=4 --recursive %1\%%i\%FORMAT_FILE%
:: 			call :REVERSE_DIR %1\%%i
:: 		) 
:: 	) 
:: )
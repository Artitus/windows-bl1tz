rem Scheduled Tasks
REM Get rid of microsoft and internet browser tasks from the query
schtasks /query /Fo list | find "TaskName:" | find /V /I "Microsoft" | find /V /I "Windows" | find /V /I "Scoring" | find /V /I "Google" | find /V /I "Firefox" | find /V /I "Opera" > %APPDATA%\stasks.txt
echo. > %APPDATA%\stasks2.txt

REM Pick out task directories
REM Look up ENABLEDELAYEDEXPANSION to understand why my variable syntax changes from % to !
SETLOCAL ENABLEDELAYEDEXPANSION
for /F "tokens=*" %%T in (%APPDATA%\stasks.txt) do (
	set tempy=%%T
	set tempyy=!tempy:~15,100!
	echo !tempyy! >> %APPDATA%\stasks2.txt
)

REM Remove the remaining tasks
for /F "tokens=*" %%T in (%APPDATA%\stasks2.txt) do (
	set tempy=%%T
	REM for some reason, the transfer of variable > file adds a space.
	schtasks /Delete /TN "!tempy:~0,-1!" /F >> nul 2>&1
)
ENDLOCAL
@echo off
set /P strOld=<current_path.txt
set strNew=%cd%

echo ***** modify phpStudy.ini *****
set phpStudyPath=phpStudy.ini
setlocal enabledelayedexpansion
for /f "tokens=*" %%i in (%phpStudyPath%) do (
  set "var=%%i"
  if not !var!.==. (
    set "var=!var:%strOld%=%strNew%!"
    echo !var!!>>%phpStudyPath%.bk
  )
)
move /y %phpStudyPath%.bk %phpStudyPath%
echo phpStudy.ini修改完毕！

echo ***** modify httpd.conf *****
set httpdPath=.\Apache\conf\httpd.conf
setlocal enabledelayedexpansion
for /f "tokens=*" %%i in (%httpdPath%) do (
  set "var=%%i"
  if not !var!.==. (
    set "var=!var:%strOld%=%strNew%!"
    echo !var!!>>%httpdPath%.bk
  )
)
 
move /y %httpdPath%.bk %httpdPath%
echo httpd.conf修改完毕！

echo ***** modify php.ini *****
set phpPath=.\PHP\php.ini
setlocal enabledelayedexpansion
for /f "tokens=*" %%i in (%phpPath%) do (
  set "var=%%i"
  if not !var!.==. (
    set "var=!var:%strOld%=%strNew%!"
    echo !var!!>>%phpPath%.bk
  )
)
 
move /y %phpPath%.bk %phpPath%
echo php.ini修改完毕！

echo %cd%> current_path.txt
pause
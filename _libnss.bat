@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\vcvars32.bat"
SET PYTHON=Python27
cl -nologo -MD -Oxb2 -LD -IC:/%PYTHON%/include -I"C:\usr\mozilla\nss-3.27\dist\public\nss" -I "C:\usr\mozilla\nss-3.27\dist\WIN954.0_OPT.OBJ\include" _libnss.c C:/%PYTHON%/libs/%PYTHON%.lib "C:\usr\mozilla\nss-3.27\dist\WIN954.0_OPT.OBJ\lib\NSS3.LIB" user32.lib /link /out:_libnss.pyd
for %%e in (obj exp lib) do del _libnss.%%e
pause

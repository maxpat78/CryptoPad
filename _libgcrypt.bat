@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\vcvars32.bat"
SET PYTHON=Python27
cl -nologo -MD -Oxb2 -LD -IC:/%PYTHON%/include -I"C:\Program Files (x86)\GnuPG\include" _libgcrypt.c C:/%PYTHON%/libs/%PYTHON%.lib "C:\Program Files (x86)\GnuPG\lib\libgcrypt.imp" user32.lib /link /out:_libgcrypt.pyd
for %%e in (obj exp lib) do del _libgcrypt.%%e
pause

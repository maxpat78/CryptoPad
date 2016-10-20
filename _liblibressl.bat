REM This uses _libeay.c but has to be statically linked with libressl at compile time!
REM libressl 2.5 actually encripts faster than openssl 1.1 and as fast as NSS 3.27! 
@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\vcvars32.bat"
SET PYTHON=Python27
cl -nologo -MD -Oxb2 -LD -IC:/%PYTHON%/include -I"libressl\include" _libeay.c C:/%PYTHON%/libs/%PYTHON%.lib "libressl\x86\libcrypto-38.lib" user32.lib /link /out:_libeay.pyd
for %%e in (obj exp lib) do del _libeay.%%e
pause

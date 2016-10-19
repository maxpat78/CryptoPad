@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\vcvars32.bat"
SET PYTHON=Python27
cl -nologo -MD -Oxb2 -LD -IC:/%PYTHON%/include -I"C:\usr\devel\Botan-1.11.31\build\include" _libbotan.c C:/%PYTHON%/libs/%PYTHON%.lib "C:\usr\devel\Botan-1.11.31\botan.lib" user32.lib /link /out:_libbotan.pyd
for %%e in (obj exp lib) do del _libbotan.%%e
pause

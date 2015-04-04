@echo off
SET PYTHON=Python27
cl -nologo -MD -O2 -LD -IC:/%PYTHON%/include -IC:\OpenSSL-Win32\include _libeay.c C:/%PYTHON%/libs/%PYTHON%.lib C:\OpenSSL-Win32\lib\VC\libeay32MD.lib user32.lib /link /out:_libeay.pyd
for %%e in (obj exp lib) do del _libeay.%%e

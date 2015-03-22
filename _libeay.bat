@echo off
cl -nologo -MD -O2 -LD -IC:/Python27/include -IC:\OpenSSL-Win32\include _libeay.c C:/Python27/libs/python27.lib C:\OpenSSL-Win32\lib\VC\libeay32MD.lib user32.lib /link /out:_libeay.pyd
for %%e in (obj exp lib) do del _libeay.%%e

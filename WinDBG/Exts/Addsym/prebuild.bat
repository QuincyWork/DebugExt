@echo off
pushd ..
set DBGSDK_INC_PATH=F:\windbg\sdk\inc
set DBGSDK_LIB_PATH=F:\windbg\sdk\lib
set DBGLIB_LIB_PATH=F:\windbg\sdk\lib
@call C:\WinDDK\7600.16385.1\bin\setenv.bat C:\WinDDK\7600.16385.1\ fre x86 WXP
popd
build -cZMg
copy objfre_wxp_x86\i386\addsym.dll  F:\windbg\winext\. /y

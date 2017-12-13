echo OFF
pushd ..
@Call "C:\Program Files\Microsoft Visual Studio 10.0\VC\vcvarsall.bat" x86
popd
cl /nologo /LD /W4 /analyze /Fegenidasym.plw genidasym.cpp user32.lib
setlocal

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"

if /I [%1] == [rebuild] (
	set option="-t:Rebuild"
)

msbuild libraop.sln /p:Configuration=Release /p:Platform=x86 %option%
msbuild libraop.sln /p:Configuration=Debug /p:Platform=x86 %option%

set target=targets\win32\x86

if exist %target% (
	del %target%\*.lib
)

robocopy lib\win32\x86 %target% lib*.lib lib*.pdb /NDL /NJH /NJS /nc /ns /np
robocopy src targets\include raop_client.h /NDL /NJH /NJS /nc /ns /np
robocopy src targets\include raop_server.h /NDL /NJH /NJS /nc /ns /np
robocopy src targets\include raop_streamer.h /NDL /NJH /NJS /nc /ns /np

endlocal


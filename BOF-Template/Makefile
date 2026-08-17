# BOF-Template Makefile for NMake
CFLAGS=/c /GS- /std:c++20 /D_HAS_EXCEPTIONS=0 /GR-
DEBUGCFLAGS=/Zi /MDd /D_DEBUG /EHsc /std:c++20
PYTHON=python

!IF "$(PROCESSOR_ARCHITECTURE)" != "x86" && "$(PROCESSOR_ARCHITECTURE)" != "AMD64"
!ERROR Only x86 and AMD64 architectures are supported or the PROCESSOR_ARCHITECTURE environment variable is not set.
!ELSEIF "$(PROCESSOR_ARCHITECTURE)" == "AMD64"
OUTDIR=..\x64\Release
IMDIR=x64\Release
DOUTDIR=..\x64\Debug
DIMDIR=x64\Debug
OUTEXT=.x64.o
!ELSE
OUTDIR=..\Release
IMDIR=Release
DIMDIR=Debug
DOUTDIR=..\Debug
OUTEXT=.x86.o
!ENDIF

# Root .cpp files -> standalone COFFs for Cobalt Strike
COFF_TARGETS=$(IMDIR)\bof.obj

all: $(COFF_TARGETS)
    @if not exist "$(OUTDIR)\" mkdir "$(OUTDIR)\"
    copy "$(IMDIR)\*.obj" "$(OUTDIR)\"
    @if exist "$(OUTDIR)\*$(OUTEXT)" del /F "$(OUTDIR)\*$(OUTEXT)"
    ren "$(OUTDIR)\*.obj" "*$(OUTEXT)"

all-debug: bof.exe

# Async framework COFFs
ASYNC_TARGETS=$(IMDIR)\async_bof.obj $(IMDIR)\async_bof_patch.obj $(IMDIR)\async_protocol.obj

async-coff: $(ASYNC_TARGETS)
    @if not exist "$(OUTDIR)\" mkdir "$(OUTDIR)\"
    copy "$(IMDIR)\async_*.obj" "$(OUTDIR)\"
    @if exist "$(OUTDIR)\*$(OUTEXT)" del /F "$(OUTDIR)\*$(OUTEXT)"
    ren "$(OUTDIR)\async_*.obj" "async_*$(OUTEXT)"

# Example COFFs (compiled with async framework as single combined COFF)
EXAMPLE_TARGETS=$(IMDIR)\async_monitor_logon.obj $(IMDIR)\async_monitor_process.obj $(IMDIR)\async_portscan.obj

example-coff: $(EXAMPLE_TARGETS)
    @if not exist "$(OUTDIR)\" mkdir "$(OUTDIR)\"
    copy "$(IMDIR)\async_monitor_logon.obj" "$(OUTDIR)\"
    copy "$(IMDIR)\async_monitor_process.obj" "$(OUTDIR)\"
    copy "$(IMDIR)\async_portscan.obj" "$(OUTDIR)\"
    @if exist "$(OUTDIR)\*$(OUTEXT)" del /F "$(OUTDIR)\*$(OUTEXT)"
    ren "$(OUTDIR)\*.obj" "*$(OUTEXT)"

.cpp{$(IMDIR)\}.obj:
    @if not exist "$(IMDIR)\" mkdir "$(IMDIR)\"
    $(CPP) $(CFLAGS) /Fo"$@" $<

    @(where $(PYTHON) >nul 2>nul \
        && $(PYTHON) --version >nul 2>nul \
        || (echo [*] Install Python to enable boflint && exit /b 0) \
    ) && $(PYTHON) utils\boflint.py --logformat vs --loader cs "$@"

# Framework .c files in async/ subdirectory
{async}.c{$(IMDIR)\}.obj:
    @if not exist "$(IMDIR)\" mkdir "$(IMDIR)\"
    $(CPP) $(CFLAGS) /Fo"$@" $<

# Example BOFs: .c from examples/ includes the async framework sources itself,
# producing a single self-contained COFF. MSVC /Fo cannot name a file with
# multiple sources (D8036), hence the framework sources are #included inside
# each example TU rather than passed as separate files to cl.
{examples}.c{$(IMDIR)\}.obj:
    @if not exist "$(IMDIR)\" mkdir "$(IMDIR)\"
    $(CPP) $(CFLAGS) /Fo"$@" $<

bof.exe: bof.cpp base\mock.cpp base\mock_async.cpp async\async_bof_proxy.cpp async\async_bof.c async\async_bof_patch.c async\async_protocol.c
    @if not exist "$(DIMDIR)\" mkdir "$(DIMDIR)\"
    @if not exist "$(DOUTDIR)\" mkdir "$(DOUTDIR)\"
    $(CPP) $(DEBUGCFLAGS) /Fo$(DIMDIR)\ /Fd$(DIMDIR)\ /Fe"$(DOUTDIR)\$@" bof.cpp base\mock.cpp base\mock_async.cpp async\async_bof_proxy.cpp async\async_bof.c async\async_bof_patch.c async\async_protocol.c

clean:
     @if exist "$(DIMDIR)\" rmdir /Q /S "$(DIMDIR)\"
     @if exist "$(IMDIR)\" rmdir /Q /S "$(IMDIR)\"
     @if exist "$(OUTDIR)\" rmdir /Q /S "$(OUTDIR)\"

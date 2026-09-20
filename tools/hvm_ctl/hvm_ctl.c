/* Standalone entry point. GUI and CLI compile the same catalog and engine. */
#include "HvmCommandCatalog.c"
#include "HvmCommandEngine.c"

int wmain(int argc, wchar_t** argv)
{
    return KswordHvmCommandMainWide(argc, argv);
}

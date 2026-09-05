#pragma once
#include <string>
bool CiPatchSeCiCallbacks(); // patch via HwRwDrv physical memory, true if patched
bool CiRestoreSeCiCallbacks(); // restore

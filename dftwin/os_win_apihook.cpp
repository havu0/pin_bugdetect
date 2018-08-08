
#include <iostream>
#include <map>
#include <set>
#include <list>
#include <assert.h>

#include "pin.H"
#include "libdft_api.h"
#include "os_win_apihook.h"
#include "tagmap.h"
#include "knob.h"
#include "tracker_etctaint.h"

#define IPOINT_After IPOINT_AFTER
#define IPOINT_Before IPOINT_BEFORE
#define Hooker(name, when) name##when
#define QUOTE(a) #a
#define Hook(name, when, func, ...) \
    rtn = RTN_FindByName(img, name); \
if (RTN_Valid(rtn)) { \
 RTN_Open(rtn); \
    RTN_InsertCall(rtn, IPOINT_##when, (AFUNPTR)func, __VA_ARGS__, IARG_END); \
    RTN_Close(rtn); \
}

extern std::ostream * out;
extern std::vector<std::string> trackNames;

namespace OSDEP {
    namespace W {
    #include <Windows.h>
    }
}




struct readfiledata {
    OSDEP::W::HANDLE hFile;
    OSDEP::W::LPVOID lpBuffer;
    OSDEP::W::LPDWORD lpNumberOfBytesRead;
	OSDEP::W::DWORD nNumberOfBytesRead;
	OSDEP::W::DWORD start_offset;
};

struct HEAP_INFO {
    ADDRINT base;
    ADDRINT size;
};

extern bool GLOB(now_tainting);
map<THREADID, set<REG>*> GLOB(reg_set);
map<THREADID, struct readfiledata*> GLOB(readfile_data);
map<THREADID, bool> GLOB(taint_this);
OSDEP::W::DWORD target_dwVolumeSerialNumber = 0;
string GLOB(targetfilename_tobetainted);
list<OSDEP::W::HANDLE> file_handles;
list<OSDEP::W::HANDLE> file_mapping_handles;

PIN_LOCK rmInst_Lock;



bool is_tainted_file(OSDEP::W::HANDLE handle) {
    PIN_LockClient();
    int ret = (find(begin(file_handles), end(file_handles), handle) != end(file_handles));
    PIN_UnlockClient();
    return ret;
}

bool is_tainted_map_file(OSDEP::W::HANDLE handle) {
    PIN_LockClient();
    int ret = find(begin(file_mapping_handles), end(file_mapping_handles), handle) != end(file_mapping_handles);
    PIN_UnlockClient();
    return ret;
}

VOID taint_file(OSDEP::W::HANDLE handle) {
    PIN_LockClient();
    file_handles.push_back(handle);
    // *out << "[TAINT FILE " << handle << " ]\n";
    PIN_UnlockClient();
}

VOID untaint_file(OSDEP::W::HANDLE handle) {
    PIN_LockClient();
    file_handles.remove(handle);
    PIN_UnlockClient();
}

VOID taint_map_file(OSDEP::W::HANDLE handle) {
    PIN_LockClient();
    file_mapping_handles.push_back(handle);
    // *out << "[TAINT FILE " << handle << " ]\n";
    PIN_UnlockClient();
}

VOID untaint_map_file(OSDEP::W::HANDLE handle) {
    PIN_LockClient();
    file_mapping_handles.remove(handle);
    PIN_UnlockClient();
}


void Hooker(ReadFile, Before) (THREADID tid, OSDEP::W::HANDLE hFile, OSDEP::W::LPVOID lpBuffer, OSDEP::W::LPDWORD lpNumberOfBytesRead, ADDRINT nNumberOfBytesRead)
{
    PIN_LockClient();
	// *out << "[DEBUG] ReadFile :: Before : " << hFile << '\n';
    if (is_tainted_file(hFile)) {
		// *out << "[DEBUG] ReadFile :: Before(tainted) : " << hFile << '\n';
        assert (GLOB(readfile_data)[tid] = new struct readfiledata);
        GLOB(readfile_data)[tid]->hFile = hFile;
        GLOB(readfile_data)[tid]->lpBuffer = lpBuffer;
        GLOB(readfile_data)[tid]->lpNumberOfBytesRead = lpNumberOfBytesRead;
		GLOB(readfile_data)[tid]->nNumberOfBytesRead = nNumberOfBytesRead;
		GLOB(readfile_data)[tid]->start_offset = OSDEP::W::SetFilePointer(hFile, 0, 0, 1);
    }
    else {
        GLOB(readfile_data)[tid] = 0;
    }
    PIN_UnlockClient();
}

VOID Hooker(ReadFile, After)(THREADID tid, ADDRINT ret)
{
    PIN_GetLock(&rmInst_Lock, 0);
	// *out << "ReadFile After\n";
    if (GLOB(readfile_data).find(tid) != GLOB(readfile_data).end() && GLOB(readfile_data)[tid]) {
		// *out << "[DEBUG] ReadFile :: After(readfile_data) : " << tid << '\n';
        if (ret && is_tainted_file(GLOB(readfile_data)[tid]->hFile)) {
			// *out << "[DEBUG] ReadFile :: After(tainted) : " << GLOB(readfile_data)[tid]->hFile << '\n';
            OSDEP::W::DWORD numberOfBytesRead;
			if(GLOB(readfile_data)[tid]->lpNumberOfBytesRead == 0)
				numberOfBytesRead = GLOB(readfile_data)[tid]->nNumberOfBytesRead;
			else
				PIN_SafeCopy(&numberOfBytesRead, GLOB(readfile_data)[tid]->lpNumberOfBytesRead, sizeof(OSDEP::W::DWORD));
            tagmap_setn((ADDRINT)GLOB(readfile_data)[tid]->lpBuffer, numberOfBytesRead);
			tracker_file_read((ADDRINT)GLOB(readfile_data)[tid]->lpBuffer, numberOfBytesRead, GLOB(readfile_data)[tid]->start_offset);
            // *out << "start tainting : " << numberOfBytesRead << '\n';
			if(GLOB(now_tainting) != true) {
				GLOB(now_tainting) = true;
				PIN_RemoveInstrumentation();
			}
        }
        delete GLOB(readfile_data)[tid];
        GLOB(readfile_data).erase(tid);
    }
    else {
        //assert (0);
    }
    PIN_ReleaseLock(&rmInst_Lock);
}

VOID Hooker(CreateFileMappingW, After) (ADDRINT ret, OSDEP::W::HANDLE handle) {
    /*
    if (ret == 0) return;
    PIN_LockClient();
    if (is_tainted_file(handle)) {
        *out << "CreateFileMappingW(tainted) :: handle : " << handle << " ret : " << hex << ret << '\n';
        taint_map_file((OSDEP::W::HANDLE)ret);
    }
    PIN_UnlockClient();
    */
}

VOID CreateFileWAfter (THREADID tid, OSDEP::W::HANDLE ret ) {
	PIN_LockClient();
	// *out << "[DEBUG] CreateFileW :: After : " << ret << '\n';
    if (ret != (OSDEP::W::HANDLE)-1) {
        
        if (GLOB(taint_this)[tid] == 1) {
			LOG("Taint start\n");
            taint_file(ret);
			// *out << "[DEBUG] CreateFileW :: After(tainted) : " << ret << '\n';
        }
	}
	PIN_UnlockClient();
}

VOID Hooker(CreateFileMappingA, After) (ADDRINT ret, OSDEP::W::HANDLE handle) {
    if (ret == 0) return;
    if (is_tainted_file(handle)) {
        Hooker(CreateFileMappingW, After)(ret, handle);
    }
}

VOID Hooker(MapViewOfFileEx, After) (ADDRINT ret, OSDEP::W::HANDLE handle, ADDRINT start_offset) {
    
    if (ret == 0) return;
    PIN_GetLock(&rmInst_Lock, 0);
	// *out << "[DEBUG] MapViewOfFileEx :: After : " << handle << '\n';
    if (is_tainted_map_file(handle) || is_tainted_file(handle)) {
        OSDEP::W::MEMORY_BASIC_INFORMATION lpBuffer;
        OSDEP::W::VirtualQuery((OSDEP::W::LPVOID)ret, &lpBuffer, sizeof(lpBuffer));
        tagmap_setn(ret, lpBuffer.RegionSize);
		tracker_file_read(ret, lpBuffer.RegionSize, start_offset);
        // *out << "MapViewOfFileEx :: tainted\n";
		if(GLOB(now_tainting) != true) {
			GLOB(now_tainting) = true;
			PIN_RemoveInstrumentation();
		}
    }
    PIN_ReleaseLock(&rmInst_Lock);

}

VOID Hooker(MapViewOfFile, After) (ADDRINT ret, OSDEP::W::HANDLE handle, ADDRINT start_offset) {
    if (ret == 0) return;
    return Hooker(MapViewOfFileEx, After) (ret, handle, start_offset);
}

VOID Hooker(CreateFileA, After) (THREADID tid, OSDEP::W::HANDLE ret) {
    if (ret != (OSDEP::W::HANDLE)-1) {
        Hooker(CreateFileW, After)(tid, ret);
    }
}

VOID CreateFileWBefore (THREADID tid, const wchar_t *path) {
    PIN_LockClient();
    wstring wstr(path);
    string str(wstr.begin(), wstr.end());
    // *out << "[DEBUG] CreateFileW :: Before : " << str << '\n'; //*out << "[OPEN FILE " << str << "]\n"
	for(auto i = trackNames.begin(); i != trackNames.end(); i++) {
		string my_trackpath(*i);
		wstring my_trackpath_w(my_trackpath.begin(), my_trackpath.end());
		LOG(str);
		LOG(" ");
		LOG(my_trackpath);
		LOG("\n");
		if (wstr.find(my_trackpath_w) != wstring::npos) {
	        GLOB(taint_this)[tid] = 1;
		}
	    else
			GLOB(taint_this)[tid] = 0;
	}
    PIN_UnlockClient();
}

VOID Hooker(CreateFileA, Before) (THREADID tid, CHAR *path) {
    PIN_LockClient();
    wstring wstr;
    string str(path);
	LOG(str);
	LOG("\n");
    wstr.assign(str.begin(), str.end());
    PIN_UnlockClient();
    Hooker(CreateFileW, Before)(tid, wstr.c_str());
}

VOID Hooker(CloseHandle, After) (OSDEP::W::HANDLE handle) {
	PIN_LockClient();
	// *out << "[DEBUG] CloseHandle :: After : " << handle << '\n';
    untaint_file(handle);
    untaint_map_file(handle);
	PIN_UnlockClient();
}

void Image(IMG img, VOID *v) {
    RTN rtn;
    // *out << "Image Loaded : " << IMG_Name(img) << endl;

    Hook("ReadFile", Before, ReadFileBefore, IARG_THREAD_ID, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_FUNCARG_ENTRYPOINT_VALUE, 2);
    Hook("ReadFile", After, ReadFileAfter, IARG_THREAD_ID, IARG_FUNCRET_EXITPOINT_VALUE);
    Hook("CreateFileA", After, CreateFileAAfter, IARG_THREAD_ID, IARG_FUNCRET_EXITPOINT_VALUE);
    Hook("CreateFileW", After, CreateFileWAfter, IARG_THREAD_ID, IARG_FUNCRET_EXITPOINT_VALUE);
    Hook("CreateFileA", Before, CreateFileABefore, IARG_THREAD_ID, IARG_FUNCARG_ENTRYPOINT_VALUE, 0);
    Hook("CreateFileW", Before, CreateFileWBefore, IARG_THREAD_ID, IARG_FUNCARG_ENTRYPOINT_VALUE, 0);
    Hook("CreateFileMappingA", After, CreateFileMappingAAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_FUNCARG_ENTRYPOINT_VALUE, 0);
    Hook("CreateFileMappingW", After, CreateFileMappingWAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_FUNCARG_ENTRYPOINT_VALUE, 0);
    Hook("MapViewOfFile", After, MapViewOfFileAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 3);
    Hook("MapViewOfFileEx", After, MapViewOfFileExAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 3);
    Hook("CloseHandle", After, CloseHandleAfter, IARG_FUNCARG_ENTRYPOINT_VALUE, 0);

}






















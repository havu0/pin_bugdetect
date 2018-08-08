#include "bugdetect.h"

VOID BOFBefore_Single( ADDRINT dst, UINT dst_size, ADDRINT src, UINT bytes, ADDRINT eip){
   //UINT src_len = strlen((char *)src);
   //UINT dst_len = strlen((char *)dst);
   UINT bytes_tainted = tagmap_issetn(bytes, 4);
   UINT dstsize_tainted = (dst_size == -1) ? 0 : tagmap_issetn(dst_size, 4);
   //UINT dst_tainted = tagmap_issetn((size_t)dst, dst_len);
   //UINT src_tainted = tagmap_issetn((size_t)src, src_len);
   int i;
   DTree *cur_tree;

   if(bytes_tainted){
	   for(i = 0; i < 4; i++) {
		   if(cur_tree = M_GET_ADDR_HASHMAP(hm1, bytes + i, DTree *, 0))
				report_bug(BUG_POTENTIAL_BUFFER_OVERFLOW, 7, eip, cur_tree);
		}
   }
   /*
   if(dstsize_tainted){
      report_bug(BUG_POTENTIAL_BUFFER_OVERFLOW, 5, eip, M_GET_ADDR_HASHMAP(hm1, dst_size, DTree *, 0));
   }
   if(dst_tainted){
      report_bug(BUG_POTENTIAL_BUFFER_OVERFLOW, 8, eip, M_GET_ADDR_HASHMAP(hm1, (size_t)dst, DTree *, 0));
   }
   */
}

VOID BOFBefore_Wide(ADDRINT dst, ADDRINT dst_size, ADDRINT src, ADDRINT bytes, ADDRINT eip){
   //UINT src_len = wcslen((wchar_t *)src);
   //UINT dst_len = wcslen((wchar_t *)dst);
   UINT bytes_tainted = tagmap_issetn(bytes, 4);
   UINT dstsize_tainted = (dst_size == -1) ? 0 : tagmap_issetn(dst_size, 4);
   //UINT dst_tainted = tagmap_issetn((size_t)dst, dst_len*2);
   //UINT src_tainted = tagmap_issetn((size_t)src, src_len*2);
   int i;
   DTree *cur_tree;

   if(bytes_tainted){
	   for(i = 0; i < 4; i++) {
		   if(cur_tree = M_GET_ADDR_HASHMAP(hm1, bytes + i, DTree *, 0))
				report_bug(BUG_POTENTIAL_BUFFER_OVERFLOW, 7, eip, M_GET_ADDR_HASHMAP(hm1, (ADDRINT)bytes + i, DTree *, 0));
		}
   }
   /*
   if(dstsize_tainted){
			   report_bug(BUG_POTENTIAL_BUFFER_OVERFLOW, 5, eip, 0);
   }
   if(dst_tainted)
				report_bug(BUG_POTENTIAL_BUFFER_OVERFLOW, 8, eip, 0);
   }
   */
}

VOID BufferOverflow_INSInst(INS ins)
{
}

typedef const char* FUNCNAME;
#define Hook3(function_list, cb, when, ...) \
for(i=0; function_list[i]; i++){ \
      rtn = RTN_FindByName(img, function_list[i]); \
   if (RTN_Valid(rtn)) {\
      RTN_Open(rtn); \
      printf("Hooked [%s]\n", function_list[i]);\
       RTN_InsertCall(rtn, when, (AFUNPTR)cb, __VA_ARGS__, IARG_END); \
       RTN_Close(rtn); \
   } \
}
VOID BufferOverflow_IMGInst(IMG img, VOID *v )
{
   RTN rtn;
   unsigned char i;
   FUNCNAME unsafe_single_dest_src_bytes[] = {"memcpy", "_fmemcpy", "memmove", "_fmemmove", 0};
   FUNCNAME unsafe_single_src_dest_bytes[] = {"bcopy", "strncpy", "_fstrncpy", 0};
   FUNCNAME unsafe_wchar_dest_src_bytes[] = {"wmemmove", "wmemcpy", 0};
   FUNCNAME unsafe_wchar_src_dest_bytes[] = {"wcsncpy", 0};
   FUNCNAME safe_single_dest_sizeofdest_src_bytes[] = {"memmove_s", "strncpy_s_", "mbsncpy_s", 0};
   FUNCNAME safe_single_dest_bytes_src[] = {"strcpy_s", "_mbscpy_s", 0};
   FUNCNAME safe_wchar_dest_sizeofdest_src_bytes[] = {"memmove_s", "strncpy_s_", "mbsncpy_s", 0};
   FUNCNAME safe_wchar_dest_bytes_src[] = {"wcscpy_s", 0};
   FUNCNAME safe_wchar_dest_src_bytes[] = {"wcsncpy_s", "wcsncpy", 0};
   
   // unsafe single func(dest, src, bytes);
   Hook3(unsafe_single_dest_src_bytes, BOFBefore_Single, IPOINT_BEFORE,
      IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
      IARG_ADDRINT, -1, // -1 for no dst_size
      IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
      IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2,
      IARG_RETURN_IP);

   // unsafe single func(src, dest, bytes);
   Hook3(unsafe_single_src_dest_bytes, BOFBefore_Single, IPOINT_BEFORE,
      IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
      IARG_ADDRINT, -1, // -1 for no dst_size
      IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
      IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2,
      IARG_RETURN_IP);

   // unsafe wchar func(dest, src, bytes);
   Hook3(unsafe_wchar_dest_src_bytes, BOFBefore_Wide, IPOINT_BEFORE,
      IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
      IARG_ADDRINT, -1, // -1 for no dst_size,
      IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
      IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2,
      IARG_RETURN_IP);

   // unsafe wchar func(src, dest, bytes);
   Hook3(unsafe_wchar_src_dest_bytes, BOFBefore_Wide, IPOINT_BEFORE,
      IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
      IARG_ADDRINT, -1, // -1 for no dst_size
      IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
      IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2,
      IARG_RETURN_IP);

   // safe single func(dest, sizeof(dest), src, bytes);
   Hook3(safe_single_dest_sizeofdest_src_bytes, BOFBefore_Single, IPOINT_BEFORE,
      IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
      IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
      IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
      IARG_FUNCARG_ENTRYPOINT_REFERENCE, 3,
      IARG_RETURN_IP);
   // safe single func(dest, bytes, src);
   Hook3(safe_single_dest_bytes_src, BOFBefore_Single, IPOINT_BEFORE,
      IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
      IARG_ADDRINT, -1,
      IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
      IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
      IARG_RETURN_IP);

   // safe wchar func(dest, sizeof(dest), src, bytes);
   Hook3(safe_wchar_dest_sizeofdest_src_bytes, BOFBefore_Wide, IPOINT_BEFORE,
      IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
      IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
      IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
      IARG_FUNCARG_ENTRYPOINT_REFERENCE, 3,
      IARG_RETURN_IP);
   //BOFBefore_Wide(wchar_t *dst, UINT dst_size, wchar_t *src, UINT bytes, ADDRINT eip, std::string *rtn_name)
   // safe wchar func(dest, bytes, src);
   Hook3(safe_wchar_dest_bytes_src, BOFBefore_Wide, IPOINT_BEFORE,
      IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
      IARG_ADDRINT, -1,
      IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
      IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
      IARG_RETURN_IP);
   // safe wchar func(dest, src, bytes);
   Hook3(safe_wchar_dest_src_bytes, BOFBefore_Wide, IPOINT_BEFORE,
      IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
      IARG_ADDRINT, -1,
      IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
      IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2,
      IARG_RETURN_IP);

}
VOID plugin_BufferOverflow()
{
   printf("IN BOF_IMGInst\n");
   IMG_AddInstrumentFunction(BufferOverflow_IMGInst, 0);
   // INS_AddInstrumentFunction(BufferOverflow_INSInst, 0);
   //ins_set_pre_all(BufferOverflow_INSInst);
}
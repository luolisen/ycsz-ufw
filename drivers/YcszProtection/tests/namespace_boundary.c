/* Execute production path predicates with portable Unicode API shims. */
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <wchar.h>
#include <wctype.h>
#define _In_
#define TRUE 1
#define FALSE 0
typedef int BOOLEAN;
typedef unsigned short USHORT;
typedef wchar_t WCHAR;
typedef struct { USHORT Length; WCHAR *Buffer; } UNICODE_STRING, *PUNICODE_STRING;
static BOOLEAN RtlPrefixUnicodeString(PUNICODE_STRING a,PUNICODE_STRING b,int insensitive) {
    size_t i;
    if(a->Length>b->Length) return 0;
    for(i=0;i<a->Length/sizeof(WCHAR);i++) {
        if(insensitive ? towlower(a->Buffer[i])!=towlower(b->Buffer[i]) : a->Buffer[i]!=b->Buffer[i]) return 0;
    }
    return 1;
}
#include "namespace_extracted.inc"
static UNICODE_STRING u(WCHAR *s) { UNICODE_STRING r={(USHORT)(wcslen(s)*sizeof(WCHAR)),s}; return r; }
int main(void) {
    UNICODE_STRING root=u(L"\\Device\\Disk1\\ProgramData\\YcszFirewall");
    WCHAR *ancestors[]={L"\\Device\\Disk1",L"\\Device\\Disk1\\ProgramData",L"\\device\\disk1\\programdata"};
    WCHAR *others[]={L"",L"\\Device\\Disk",L"\\Device\\Disk2",L"\\Device\\Disk1\\Program",L"\\Device\\Disk1\\ProgramData2",L"\\Device\\Disk1\\ProgramData\\YcszFirewall",L"\\Device\\Disk1\\ProgramData\\YcszFirewall\\state.db",L"\\Device\\Disk1\\Other"};
    size_t i;
    for(i=0;i<sizeof(ancestors)/sizeof(*ancestors);i++) { UNICODE_STRING p=u(ancestors[i]); assert(YcpPathIsStrictAncestor(&p,&root)); }
    for(i=0;i<sizeof(others)/sizeof(*others);i++) { UNICODE_STRING p=u(others[i]); assert(!YcpPathIsStrictAncestor(&p,&root)); }
    assert(!YcpPathIsStrictAncestor(NULL,&root));
    assert(!YcpPathIsStrictAncestor(&root,NULL));
    puts("PASS 13 namespace boundary cases; genuine ancestors only, no sibling or prefix collision");
    return 0;
}

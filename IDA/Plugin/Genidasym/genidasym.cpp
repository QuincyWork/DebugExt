#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

#pragma pack(1)
typedef struct _INF
{
    byte unk[43];
    unsigned long MinEa;
} Inf, *PInf;

typedef struct _IDAINIT
{
    int version;
    int flags;
    int (__stdcall * init)(void);
    void (__stdcall * term)(void);
    void (__stdcall * run)(int arg);
    char *comment;
    char *help;
    char *plgname;
    char *hotkey;
} IdaInit, *PIdaInit;

typedef int             ( __stdcall *g_size             ) (void);       
typedef unsigned long   ( __stdcall *g_ea 	            ) (int index);
typedef char*           ( __stdcall *g_name 	        ) (int index);
typedef int             ( __stdcall *g_inputfilepath    ) (int index,char * buff,int buffsize);
typedef void*           ( __stdcall *g_inf              ) (void);

g_size           get_nlist_size = 0;
g_ea             get_nlist_ea = 0;
g_name           get_nlist_name = 0;
g_inputfilepath  netnode_valstr = 0;
g_inf            inf = 0;
HINSTANCE	hdllinst = 0;

BOOL WINAPI DllEntryPoint( HINSTANCE hi, DWORD reason, LPVOID reserved ) {
    UNREFERENCED_PARAMETER( reserved );
    if (reason==DLL_PROCESS_ATTACH)
        hdllinst=hi;
    return 1;
};

int __stdcall init(void)
{
    return 1;
}

void __stdcall run(int)
{
    HMODULE hMod;

    if ( ( hMod = LoadLibrary("Ida.wll") ) == NULL )
    {
        MessageBox( NULL, "Cannot Loadlib ida.wll" , "Error_LoadLib" , NULL );
        return;
    }

    if ( ( get_nlist_size = (g_size) GetProcAddress(hMod, "get_nlist_size") ) == NULL)
    {
        if ( ( get_nlist_size = (g_size) GetProcAddress(hMod,MAKEINTRESOURCE(383)) ) == NULL)
        {
            MessageBox(NULL,"Cannot resolve ProcAddress of get_nlist_size" , "Error GetProc genidasym plugin" ,NULL);
            return ;
        }
    }

    if ( ( get_nlist_ea = (g_ea) GetProcAddress(hMod, "get_nlist_ea") ) == NULL)
    {
        if ( ( get_nlist_ea = (g_ea) GetProcAddress(hMod,MAKEINTRESOURCE(40)) ) == NULL)
        {
            MessageBox(NULL,"Cannot resolve ProcAddress of get_nlist_ea" , "Error GetProc genidasym plugin" ,NULL);
            return ;
        }
    }

    if ( ( get_nlist_name = (g_name) GetProcAddress(hMod, "get_nlist_name") ) == NULL)
    {
        if ( ( get_nlist_name = (g_name) GetProcAddress(hMod,MAKEINTRESOURCE(252)) ) == NULL)
        {
            MessageBox(NULL,"Cannot resolve ProcAddress of get_nlist_name" , "Error GetProc genidasym plugin" ,NULL);
            return ;
        }
    }

    if ( ( netnode_valstr = (g_inputfilepath) GetProcAddress(hMod, "netnode_valstr") ) == NULL)
    {
        if ( ( netnode_valstr = (g_inputfilepath) GetProcAddress(hMod,MAKEINTRESOURCE(811)) ) == NULL)
        {
            MessageBox(NULL,"Cannot resolve ProcAddress of netnode_valstr" , "Error GetProc genidasym plugin" ,NULL);
            return ;
        }
    }

    if ( ( inf = (g_inf) GetProcAddress(hMod, "inf") ) == NULL)
    {
        if ( ( inf = (g_inf) GetProcAddress(hMod,MAKEINTRESOURCE(416)) ) == NULL)
        {
            MessageBox(NULL,"Cannot resolve ProcAddress of inf" , "Error GetProc genidasym plugin" ,NULL);
            return ;
        }
    }

    char inputfilepath[0x250];
    char outputfilepath[0x100];
    memset (&inputfilepath,0,0x250);
    memset (&outputfilepath,0,0x100);
    unsigned long dos_elfaw = 0;
    unsigned long baseofcode = 0;
    unsigned long ImageBase = 0;
    FILE *fp = 0;
    errno_t err = 0;
    int fseekret = 0;
    size_t freadret = 0;

    int size = get_nlist_size();

    netnode_valstr(0xff000001,inputfilepath,0x200);

    if (( err = fopen_s(&fp,inputfilepath,"rb") ) != NULL)
    {
        MessageBox(NULL,"Cannot open inputfile" , "Error opening input file idasym plugin" ,NULL);
        return ;
    }

    if (( fseekret = fseek(fp,0x3c,SEEK_SET) ) != NULL)
    {
        MessageBox(NULL,"Cannot fseek inputfile" , "Error seeking dos_elfaw_new in input file idasym plugin" ,NULL);
        return ;
    }

    if (( freadret =  fread(&dos_elfaw,sizeof(unsigned long),1,fp) ) != 1)
    {
        MessageBox(NULL,"fread dos_elfaw_new didnt read required count of items" , "Error fread idasym plugin" ,NULL);
        return ;
    }

    if (( fseekret =  fseek(fp,dos_elfaw+0x2c,SEEK_SET) ) != NULL)
    {
        MessageBox(NULL,"Cannot fseek inputfile" , "Error seeking baseofcode in input file idasym plugin" ,NULL);
        return ;
    }

    if (( freadret =  fread(&baseofcode,sizeof(unsigned long),1,fp) ) != 1)
    {
        MessageBox(NULL,"fread baseofcode didnt read required count of items" , "Error fread idasym plugin" ,NULL);
        return ;
    }

    if (( fseekret =   fseek(fp,dos_elfaw+0x34,SEEK_SET) ) != NULL)
    {
        MessageBox(NULL,"Cannot fseek inputfile" , "Error seeking ImageBase in input file idasym plugin" ,NULL);
        return ;
    }

    if (( freadret =  fread(&ImageBase,sizeof(unsigned long),1,fp) ) != 1 )
    {
        MessageBox(NULL,"fread imagebase didnt read required count of items" , "Error fread idasym plugin" ,NULL);
        return ;
    }

    if (( err =  fclose(fp) ) != NULL)
    {
        MessageBox(NULL,"Cannot close inputfile" , "Error closing input file idasym plugin" ,NULL);
        return ;
    }

    unsigned long tosubtract;

    if ( (((PInf)inf)->MinEa) == ImageBase )  
    {
        tosubtract = ImageBase;
    }
    else if ( (((PInf)inf)->MinEa) == (ImageBase + baseofcode) )
    {
        tosubtract = ImageBase;
    }
    else
    {
        tosubtract = ( ((PInf)inf)->MinEa - baseofcode );
    }

    FILE * symfile;
    char * symfilename = strrchr( inputfilepath ,'\\');

    sprintf_s(outputfilepath,"c:\\idasym%s.idasym\0",symfilename);

    if (( err = fopen_s(&symfile,outputfilepath,"w") ) != NULL)
    {
        MessageBox(NULL,"Cannot open outputfile" , "Error opening output file idasym plugin" ,NULL);
        return ;
    }

    for (int i =0; i< size; i++)
    {
        unsigned long ea = get_nlist_ea(i);
        char *name = get_nlist_name(i);
        fprintf(symfile,"0x%08x,%s\n",(ea-tosubtract),name );
    }

    if (( err = fclose(symfile) ) != NULL)
    {
        MessageBox(NULL,"Cannot close outputfile" , "Error closing output file idasym plugin" ,NULL);
        return ;
    }

}

__declspec(dllexport)  IdaInit PLUGIN =
{
    'L',
    0,
    init,
    NULL,
    run,
    NULL,
    NULL,
    "genidasym",
    NULL
};

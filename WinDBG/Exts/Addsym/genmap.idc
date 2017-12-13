#include <idc.idc>
static main(void)
{
    auto temp,elfaw_new ,baseofcode,tosubtract,symfile,segstart,segend,i,outfile,symname;
    // idafree doesnt seem to know anything about pe header HACK to get stuff
    temp = fopen(GetInputFilePath(),"rb");
    fseek(temp,0x3c,0);                 //to Read IMAGE_DOS_HEADER->elfaw_new
    elfaw_new = readlong(temp,0);
    fseek(temp,(elfaw_new+0x2c),0);     //to read  _IMAGE_NT_HEADERS->OptionalHeader->BaseofCode
    baseofcode = readlong(temp,0);
    tosubtract = FirstSeg()-baseofcode;
    fclose(temp);

    symfile = "c:\\IDASYM\\" + GetInputFile() + ".idasym";    
    outfile = fopen( symfile,"w");
    if (!outfile)
    {
        Message("failed to create file %s\n check if c:\\idasym folder exists",symfile);
    }
    else
    {
        Message("creating idasym file %s\n",symfile);
        segstart = 0;
        do
        {
            segstart = NextSeg(segstart);
            segend = SegEnd(segstart);
            for ( i = 0 ; i < segend-segstart ; i++)
            {
                symname = Name( segstart+i ) ;
                // discarding DOC AND UNDOC dummy names (does pro ida have convinience funcs ? must be tedious without them :( )             
                if (   
                    (symname != "" )                    &&  
                    (substr(symname,0,4) != "sub_")     &&  
                    (substr(symname,0,7) != "locret_")  && 
                    (substr(symname,0,4) != "loc_" )    && 
                    (substr(symname,0,4) != "off_" )    &&  
                    (substr(symname,0,4) != "seg_" )    &&  
                    (substr(symname,0,4) != "asc_" )    &&
                    (substr(symname,0,5) != "byte_" )   &&
                    (substr(symname,0,5) != "word_" )   &&       
                    (substr(symname,0,6) != "dword_" )  &&
                    (substr(symname,0,5) != "qword_" )  &&
                    (substr(symname,0,4) != "flt_" )    &&  
                    (substr(symname,0,4) != "dbl_" )    &&  
                    (substr(symname,0,6) != "tbyte__" ) &&
                    (substr(symname,0,5) != "stru_" )   &&  
                    (substr(symname,0,5) != "algn_" )   &&
                    (substr(symname,0,6) != "oword_" )  &&      
                    (substr(symname,0,4) != "unk_" ) 
                    )
                { 
                    fprintf(outfile,"%08x,%s\n", ((segstart+i)-tosubtract)  , Name(  segstart+i ) );
                }
            }
        }while (segend != BADADDR);
        fclose(outfile);
    }
}
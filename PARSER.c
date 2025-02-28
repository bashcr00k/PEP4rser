//tool made by B4shCr00k
#include <stdio.h>
#include <windows.h>
#include <time.h>

#define okay(msg , ...) printf(msg"\n",##__VA_ARGS__)
#define error(msg , ...) printf("[-] "msg"\n",##__VA_ARGS__)
#define warn(msg , ...) printf("[!] "msg"\n",##__VA_ARGS__)


DWORD RvaToFileOffset(IMAGE_SECTION_HEADER *ish2,DWORD rva,int section_count)
{
    for (int i = 0; i < section_count; i++)
    {
        if (ish2[i].VirtualAddress <= rva && rva < ish2[i].VirtualAddress + ish2[i].Misc.VirtualSize)
        {
            int offset = ish2[i].PointerToRawData + (rva - ish2[i].VirtualAddress);
            return offset;
        }
        
    }
}

int main(int argc, char *argv[])
{
    char *path;
    if (argc != 2)
    {
        error("Usage : Parser.exe [FILE]");
    }
    path = argv[1];  
    
    FILE *file;
    IMAGE_DOS_HEADER idh;
    IMAGE_NT_HEADERS inh;
    IMAGE_SECTION_HEADER ish;
    IMAGE_IMPORT_DESCRIPTOR imp;
    IMAGE_THUNK_DATA ptd32;
    DWORD thunk;
    DWORD Signature;
    DWORD thunkoffset;
    DWORD namerva;
    char DllName[256];
    DWORD funcoffset;
    char funcname[256];
    
    int sectionoffset;
    
    okay("Openning File");
    file = fopen(path,"rb");
    if (file == NULL)
    {
       error("Failed To Open File");
    }
    else
    {
        okay("Filed Opened");
    }
    
    
    

    fread(&idh,sizeof(idh),1,file);
    printf("-----------DOS_HEADER---------\n\n\n");
    printf("\tMagic Number Is : 0x%x\n",idh.e_magic);
    if (idh.e_magic == 0x00005a4d)
    {
        printf("\t*Valid Magic Number");

    }
    else{warn("\tBad Magic Number");}
    
    okay("\tNt_Header At : 0x%x\n\n",idh.e_lfanew);
    printf("-----------NT_HEADER---------\n\n\n");

    fseek(file,idh.e_lfanew,0);
    fread(&inh,sizeof(inh),1,file);
    

    okay("\tSignature is 0x%x",inh.Signature);

    if (inh.Signature == 0x00004550)
    {
        printf("\t*Valid Signature\n");
    }
    else
    {
        warn("\tBad Signature");
    }
    time_t timestamp = inh.FileHeader.TimeDateStamp; 
    switch (inh.FileHeader.Machine)
    {
    case 0x0000014C:
        okay("\tARCH : 32-bit");
        break;
    case 0x00008664:
    okay("\tARCH : 64-bit");
    case 0x000001C0:
    okay("\tARCH : ARM");
    
    default:error("\t-----INVALID ARCH");
        break;
    }
    printf("\tCreation Date : %s",ctime(&timestamp));
    okay("\tNumber Of Sections : 0x%x",inh.FileHeader.NumberOfSections);
    okay("\tSize Of Optional Header : 0x%x",inh.FileHeader.SizeOfOptionalHeader);
    okay("\tAttributes : 0x%x",inh.FileHeader.Characteristics);
    if (inh.OptionalHeader.Magic == 0x0000010B)
    {
        okay("\tPE32");
    }
    else if (inh.OptionalHeader.Magic == 0x0000020B)
    {
        okay("\tPE64");
    }
    okay("\tRVA : 0x%x",inh.OptionalHeader.AddressOfEntryPoint);
    okay("\tSize Of .text : 0x%x",inh.OptionalHeader.SizeOfCode);
    okay("\tSize Of Image : 0x%x",inh.OptionalHeader.SizeOfImage);
    okay("\tImage Base : 0x%x",inh.OptionalHeader.ImageBase);
    if (inh.OptionalHeader.Subsystem == 2)
    {
        okay("\t----GUI");
    }
    else if (inh.OptionalHeader.Subsystem == 3)
    {
       okay("\t----CONSOLE");
    }
    okay("\tDll Characteristics : 0x%x\n\n", inh.OptionalHeader.DllCharacteristics);


    int SECTION_HEADER_OFFSET = idh.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + inh.FileHeader.SizeOfOptionalHeader;
    fseek(file,SECTION_HEADER_OFFSET,0);
    sectionoffset = SECTION_HEADER_OFFSET;
    int section_count = inh.FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER ish2[section_count];
    printf("-----------SECTIONS---------\n\n\n");
    for (int i = 0; i < section_count; i++)
    {   
        
        fread(&ish2[i],sizeof(IMAGE_SECTION_HEADER),1,file);
        
        char sectionName[9] = {0};  
        memcpy(sectionName, ish2[i].Name, 8);
        printf("\t%.8s\tSection Offset 0x%x\n",ish2[i].Name,SECTION_HEADER_OFFSET);
        printf("\t\tSize Of Section : 0x%x\n",ish2[i].Misc.VirtualSize);
       printf("\t\tCharacteristics : 0x%x\n",ish2[i].Characteristics);
        printf("\t\tOffset In File : 0x%x\n\n\n",ish2[i].PointerToRawData);
        sectionoffset += sizeof(IMAGE_SECTION_HEADER);
    }
    DWORD import_directory_rva = inh.OptionalHeader.DataDirectory[1].VirtualAddress;
    DWORD importoffset = RvaToFileOffset(ish2,import_directory_rva,section_count); 
    fseek(file,importoffset,0);


    printf("-----------DLLs---------\n");
        
    while (1)
    {   
        memset(funcname,sizeof(funcname),0);
        
        fread(&imp,sizeof(imp),1,file);
        if (imp.Name == 0)
        {
            break;
        }
        DWORD nameoffset = RvaToFileOffset(ish2,imp.Name,section_count);
        fseek(file,nameoffset,0);
        fread(DllName,sizeof(DllName),1,file);
        okay("\t///%s\n",DllName);
        if (imp.OriginalFirstThunk == 0)
        {
            thunk = imp.FirstThunk;
        }
        else
        {
            thunk = imp.OriginalFirstThunk;
        }
        
        thunkoffset = RvaToFileOffset(ish2,thunk,section_count);
        fseek(file,thunkoffset,0);
        while (1)
        {

            fread(&ptd32,sizeof(ptd32),1,file);
            if (ptd32.u1.AddressOfData == 0)
            {
                break;
            }
            if (ptd32.u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                okay("Ordinal: %d", ptd32.u1.Ordinal & 0xFFFF);
            }
            else
            {
                
                funcoffset = RvaToFileOffset(ish2,ptd32.u1.AddressOfData,section_count);
                
                fseek(file,funcoffset + 2,0);
                fread(&funcname,1,sizeof(funcname),file);
                funcname[255] = '\0';
                printf("-%s\n",funcname);
                thunkoffset = thunkoffset + sizeof(IMAGE_THUNK_DATA);
                fseek(file,thunkoffset,0);
            }
            
        }
        
        importoffset = importoffset + sizeof(IMAGE_IMPORT_DESCRIPTOR);
        fseek(file,importoffset,0);
    }
    fclose(file);
    return 0;    
}

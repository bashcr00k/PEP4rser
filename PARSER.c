//tool made by B4shCr00k
#include <stdio.h>
#include <windows.h>
#include <time.h>

#define okay(msg , ...) printf("[+] "msg"\n",##__VA_ARGS__)
#define error(msg , ...) printf("[-] "msg"\n",##__VA_ARGS__)
#define warn(msg , ...) printf("[!] "msg"\n",##__VA_ARGS__)

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
    IMAGE_NT_HEADERS64 inh;
    IMAGE_SECTION_HEADER ish;
    IMAGE_DATA_DIRECTORY idd;
    DWORD Signature;
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
    okay("Magic Number Is : 0x%x",idh.e_magic);
    if (idh.e_magic == 0x00005a4d)
    {
        okay("Valid Magic Number");

    }
    else{warn("Bad Magic Number");}
    
    okay("Nt_Header At : 0x%x",idh.e_lfanew);

    fseek(file,idh.e_lfanew,0);
    fread(&inh,sizeof(inh),1,file);
    

    okay("Signature is 0x%x",inh.Signature);

    if (inh.Signature == 0x00004550)
    {
        okay("Valid Signature");
    }
    else
    {
        warn("Bad Signature");
    }
    time_t timestamp = inh.FileHeader.TimeDateStamp; 
    switch (inh.FileHeader.Machine)
    {
    case 0x0000014C:
        okay("32-bit");
        break;
    case 0x00008664:
        okay("64-bit");
    case 0x000001C0:
        okay("ARM");
    
    default:okay("Invalid Arch");
        break;
    }
    printf("[+] Creation Date : %s",ctime(&timestamp));
    okay("Number Of Sections : 0x%x",inh.FileHeader.NumberOfSections);
    okay("Size Of Optional Header : 0x%x",inh.FileHeader.SizeOfOptionalHeader);
    okay("Attributes : 0x%x",inh.FileHeader.Characteristics);
    if (inh.OptionalHeader.Magic == 0x0000010B)
    {
        okay("PE32");
    }
    else if (inh.OptionalHeader.Magic == 0x0000020B)
    {
        okay("PE64");
    }
    okay("RVA : 0x%x",inh.OptionalHeader.AddressOfEntryPoint);
    okay("Size Of .text : 0x%x",inh.OptionalHeader.SizeOfCode);
    okay("Size Of Image : 0x%x",inh.OptionalHeader.SizeOfImage);
    okay("Image Base : 0x%x",inh.OptionalHeader.ImageBase);
    if (inh.OptionalHeader.Subsystem == 2)
    {
        okay("GUI");
    }
    else if (inh.OptionalHeader.Subsystem == 3)
    {
       okay("Console");
    }
    okay("Dll Characteristics : 0x%x", inh.OptionalHeader.DllCharacteristics);

    int SECTION_HEADER_OFFSET = idh.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + inh.FileHeader.SizeOfOptionalHeader;
    fseek(file,SECTION_HEADER_OFFSET,0);
    sectionoffset = SECTION_HEADER_OFFSET;
    int section_count = inh.FileHeader.NumberOfSections;
    for (int i = 0; i < section_count; i++)
    {   
        
        fread(&ish,sizeof(ish),1,file);
        okay("Section Header Offset : 0x%x",SECTION_HEADER_OFFSET);
        okay("Section Name : %.8s",ish.Name);
        okay("Size Of Section : 0x%x",ish.Misc.VirtualSize);
        okay("Characteristics : 0x%x",ish.Characteristics);
        okay("Offset In File : 0x%x",ish.PointerToRawData);
        sectionoffset = sectionoffset + 40;
    }

    return 0;    
}

# PEP4rser
A c PE parser 



# Why i wrote this 
This is a small project to learn more about pe file format since its so important for malware dev.

-What it simply does is read the pe headers and print out the different informations stored in them.
-The process was easy for the most part i will explain everything about how it works for those that are new to this since i didn't really find a lot resources that explain this topic for beginners even tho its very simple.

# What is The PE file format ?
- Its basically a structure that a binary file must follow  in order to be executable in windows,Every os has its own structure like elf for linux (executable and linkable format) for example .
- This format is so important because it contains very sensitive informations the operating system must know in order to load the binary.
- It consists of 4 important parts (there are more but we don't really care about them) so this code will parse these 4 parts

# Part 1 : The Dos Header
- this part has only two very important informations we need : The magic number and the Nt Header Offset
  The Magic number is a signature that we can use to check if its a valid pe file it should always be equal to 0x5A4D . The nt header offset is pretty much self explanatory it tells us where the nt header is located so we need these two informations in order to procees .
# Part 2 : Nt Header
- This is the most important part it contains informations such as compilation date,number of sections,import directory offset and much more
- the nt header it self consists of 3 parts.
-- A signature PE\0\0
-- Image File Header :
    it has informations such as the cpu type and the number of sections
-- Optional Header
  size of .text section,entry point rva, gui or console ...
# Part 3 : Section Header
- This part has all the sections such as .text .reloc .data .rdata
# Part 4 : Import Table
- This part has all the dlls and their informations

## Explaining the code 
The process wasn't so hard everything was going so smoothly all i was doing is reading into a structure using fread after i changed the file pointer to where the data is stored using fseek nothing complicated here and you will understand it after you read the code . 

The hard part was the Import Table, parsing the dll names with the functions imported by them was so confusing at first because it included a lot of memory reading and offset calculations but it gets simpler the more you think about it .

- Before i explain how i parsed the import table i have to explain some important definitions 
Rva : relative virtual address its basically a virtual address in relative to the pe base address which is located in the baseaddress in the optional header we talked about 
Rva = VirtualAddress - BaseAddress
File Offsets : self explanatory this is what we actually use with fseek in order to read the data with fread

 so if we have a data stored at a spesific rva we need to convert the rva to a file offset then we can actually read the data ,I did this by creating a function that calculates the offset based on an rva, let me explain how it works 

 The Formula I used is

 File Offset = Pointer To Raw Data + (RVA - Section Virtual Address)
 where 
 File Offset : What we need
 Pointer To Raw Data : The start of the section in the file
 Section Virtual Address : RVA to the start of the section 

 So we have to first figure out in which section the rva lands then we use this formula.
 to do so we loop through all sections and every time we check if the rva is bigger than the section base address and the section base address + the size of the section which is just the end of the section .
 Once we find in which section the rva falls we can use the formula to get the file offset 

 how does that formula works : 
 first we have an rva we need the file offset to that rva 
 what we do is we subtract the section virtual address from the rva this gives us the offset of the rva taking the start of the section as the beginning after that all we need to do is add the offset of the section since we calculated the offset of the rva inside the section which finally gives us the the file offset to the rva 

 ### Happy Hacking
 After this i will start working on a reflective dll injector so stay tuned.

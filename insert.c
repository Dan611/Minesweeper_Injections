#include <windows.h>
#include <stdio.h>
#include <stdint.h>

int main()
{
	char *dll = "sweeper.dll",
		 *func = "showMines",
		 *input = "Winmine__XP.exe",
		 *output = "Winmine__XD.exe",
		 *exe;

	FILE *f = fopen(input, "rb");

	if(!f)
	{
		printf("Could not locate PE file");
		return 1;
	}
	else
	{
		fseek(f, 0, SEEK_END);
		size_t size = ftell(f);
		fseek(f, 0, SEEK_SET);
		exe = (char *) malloc(size);
		fread(exe, size, 1, f);
		fclose(f);
	}

	char inject[64];
	sprintf(inject, "%s%c%c%c%s%c%c%c%c%c", dll, 0, 0, 0, func, 0, 0, 0, 0, 0); // (imported dll, imported function (thunk), OFT (address to thunk))
	size_t inject_strlen = strlen(dll) + 3 + strlen(func) + 5,
		   inject_thunk = strlen(dll) + 1;

	IMAGE_DOS_HEADER dos_header;
	IMAGE_NT_HEADERS *nt_headers_ptr;
	IMAGE_SECTION_HEADER *section_headers;
	IMAGE_IMPORT_DESCRIPTOR *import_descriptor;
	off_t physical_offset = 0,
		  physical_offset_final = 0,
		  physical_end = 0;

	dos_header = *(IMAGE_DOS_HEADER *) (exe);
	nt_headers_ptr = (IMAGE_NT_HEADERS *) (exe + dos_header.e_lfanew);

	if(dos_header.e_magic != 0x5A4D || (*nt_headers_ptr).Signature != 0x4550)
	{
		printf("Invalid PE file\n");
		free(exe);
		return 1;
	}

	section_headers = 
		(IMAGE_SECTION_HEADER *)
		(exe
		+ dos_header.e_lfanew
		+ sizeof((*nt_headers_ptr).Signature)
		+ sizeof((*nt_headers_ptr).FileHeader)
		+ (*nt_headers_ptr).FileHeader.SizeOfOptionalHeader);

	int final_section = (*nt_headers_ptr).FileHeader.NumberOfSections - 1;
		physical_offset_final = section_headers[final_section].PointerToRawData - section_headers[final_section].VirtualAddress;
		physical_end = section_headers[final_section].PointerToRawData + section_headers[final_section].SizeOfRawData;

	// find the section the imports are located in, get the physical offset for that section
	for(int i = final_section;i > -1;i--)
		if(section_headers[i].VirtualAddress <= (*nt_headers_ptr).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
		{
			physical_offset = section_headers[i].PointerToRawData - section_headers[i].VirtualAddress;
			break;
		}

	import_descriptor =
		(IMAGE_IMPORT_DESCRIPTOR *)
		(exe
		+ (*nt_headers_ptr).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
		+ physical_offset);

	int import_count = -1;
	while(import_descriptor[++import_count].OriginalFirstThunk);

	// point the import rva to the end of the final section
	(*nt_headers_ptr).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = physical_end - physical_offset_final;

	// adjust the PE to fit the new imports
	(*nt_headers_ptr).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	(*nt_headers_ptr).OptionalHeader.SizeOfImage += (*nt_headers_ptr).OptionalHeader.SectionAlignment;
	section_headers[final_section].SizeOfRawData += (*nt_headers_ptr).OptionalHeader.SectionAlignment;
	section_headers[final_section].Misc.VirtualSize += (*nt_headers_ptr).OptionalHeader.SectionAlignment;
	section_headers[final_section].Characteristics |= IMAGE_SCN_MEM_WRITE;

	intptr_t inject_addr = (import_count + 2)*sizeof(IMAGE_IMPORT_DESCRIPTOR) + physical_end - physical_offset_final;

	// set the inject's OFT address to the address of the injected thunk
	*(DWORD *) (inject + inject_strlen - 4) = inject_addr + inject_thunk;

	IMAGE_IMPORT_DESCRIPTOR new_import = (IMAGE_IMPORT_DESCRIPTOR)
	{
		// last 4 bytes of injection string are the OFT address
		.OriginalFirstThunk = inject_addr + inject_strlen - 4,
		.TimeDateStamp = 0,
		.ForwarderChain = 0,
		.Name = inject_addr,
		.FirstThunk = inject_addr + inject_strlen - 4,
	};

	FILE *o = fopen(output, "wb");

	fwrite(exe, physical_end, 1, o);

	// copy the old imports to the bottom of the last section
	fwrite(import_descriptor, import_count*sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, o);
	// append the new import
	fwrite(&new_import, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, o);
	fwrite("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, o);
	// append the injection string
	fwrite(inject, inject_strlen, 1, o); 

	// pad the file to the proper alignment
	size_t padlen = (*nt_headers_ptr).OptionalHeader.SectionAlignment - (import_count + 2)*sizeof(IMAGE_IMPORT_DESCRIPTOR) - inject_strlen;
	char *pad = (char *) calloc(1, padlen);
	fwrite(pad, padlen, 1, o);

	free(pad);
	free(exe);
	fclose(o);
	
	return 0;
}


// function to walk through the resource directories
/*void recurse_directory(int r, const char *exe, intptr_t resource_directory_start, intptr_t offset)
{
	IMAGE_RESOURCE_DIRECTORY *resource_directory = 
		(IMAGE_RESOURCE_DIRECTORY *)
		(exe 
		+ resource_directory_start
		+ offset);

	IMAGE_RESOURCE_DIRECTORY_ENTRY *resource_directory_entry = 
	(IMAGE_RESOURCE_DIRECTORY_ENTRY *)
		(exe 
		+ resource_directory_start
		+ offset
		+ sizeof(IMAGE_RESOURCE_DIRECTORY));

	for(int i = 0;i < (*resource_directory).NumberOfIdEntries + (*resource_directory).NumberOfNamedEntries;i++)
	{
		for(int t = 0;t < r;t++)
			printf("\t");

		printf("%d\n", resource_directory_entry[i].OffsetToDirectory);
		
		if(resource_directory_entry[i].DataIsDirectory)
		{
			//printf("DIR %d\n", i+1);
			recurse_directory(r + 1, exe, resource_directory_start, resource_directory_entry[i].OffsetToDirectory);
		}
		else
		{
			printf("RSC %d", i+1);

			IMAGE_RESOURCE_DATA_ENTRY *resource_data_entry =
				(IMAGE_RESOURCE_DATA_ENTRY *)
				(exe
				+ resource_directory_start
				+ resource_directory_entry[i].OffsetToDirectory);

				//printf(" %X\n", (*resource_data_entry).OffsetToData);
		}
	}
}*/
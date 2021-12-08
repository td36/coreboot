/* SPDX-License-Identifier: GPL-2.0-only */

#include <arch/hlt.h>
#include <console/console.h>
#include <hob.h>

void *hob_list;

/* Compares two EFI GUIDs. Returns true of the GUIDs match, false otherwise. */
static bool compare_guid(const EFI_GUID *guid1, const EFI_GUID *guid2)
{
	  return !memcmp(guid1, guid2, sizeof(EFI_GUID));
}

static EFI_GUID *copy_guid(EFI_GUID *dest, const EFI_GUID *src)
{
	  return (EFI_GUID *)memcpy(dest, src, sizeof(EFI_GUID));
}

/**
  Returns the pointer to the HOB list.
**/
static void *get_hob_list(void)
{
  if (!hob_list)
	  die("Hoblist is NULL\n");
  return hob_list;
}

EFI_HOB_HANDOFF_INFO_TABLE *hob_table_init(void *memory_bottom, void *memory_top,
        void *free_memory_bottom, void *free_memory_top)
{
  EFI_HOB_HANDOFF_INFO_TABLE  *hob;
  EFI_HOB_GENERIC_HEADER      *hob_end;

  hob    = free_memory_bottom;
  hob_end = (EFI_HOB_GENERIC_HEADER *)(hob+1);

  hob->Header.HobType      = EFI_HOB_TYPE_HANDOFF;
  hob->Header.HobLength    = sizeof(EFI_HOB_HANDOFF_INFO_TABLE);
  hob->Header.Reserved     = 0;

  hob_end->HobType          = EFI_HOB_TYPE_END_OF_HOB_LIST;
  hob_end->HobLength        = sizeof(EFI_HOB_GENERIC_HEADER);
  hob_end->Reserved         = 0;

  hob->Version             = EFI_HOB_HANDOFF_TABLE_VERSION;
  hob->BootMode            = BOOT_WITH_FULL_CONFIGURATION;

  hob->EfiMemoryTop        = (UINTN)memory_top;
  hob->EfiMemoryBottom     = (UINTN)memory_bottom;
  hob->EfiFreeMemoryTop    = (UINTN)free_memory_top;
  hob->EfiFreeMemoryBottom = (EFI_PHYSICAL_ADDRESS)(UINTN)(hob_end+1);
  hob->EfiEndOfHobList     = (EFI_PHYSICAL_ADDRESS)(UINTN)hob_end;

  hob_list = hob;
  return hob;
}

static void *create_hob(UINT16 hob_type, UINT16 hob_length)
{
  EFI_HOB_HANDOFF_INFO_TABLE  *handoff_hob;
  EFI_HOB_GENERIC_HEADER      *hob_end;
  EFI_PHYSICAL_ADDRESS        free_memory;
  void                        *hob;

  handoff_hob = get_hob_list();

  hob_length = (UINT16)((hob_length + 0x7) & (~0x7));

  free_memory = handoff_hob->EfiFreeMemoryTop - handoff_hob->EfiFreeMemoryBottom;

  if (free_memory < hob_length) {
      return NULL;
  }

  hob = (void*) (UINTN) handoff_hob->EfiEndOfHobList;
  ((EFI_HOB_GENERIC_HEADER*) hob)->HobType = hob_type;
  ((EFI_HOB_GENERIC_HEADER*) hob)->HobLength = hob_length;
  ((EFI_HOB_GENERIC_HEADER*) hob)->Reserved = 0;

  hob_end = (EFI_HOB_GENERIC_HEADER*) ((UINTN)hob + hob_length);
  handoff_hob->EfiEndOfHobList = (EFI_PHYSICAL_ADDRESS) (UINTN) hob_end;

  hob_end->HobType   = EFI_HOB_TYPE_END_OF_HOB_LIST;
  hob_end->HobLength = sizeof(EFI_HOB_GENERIC_HEADER);
  hob_end->Reserved  = 0;
  hob_end++;
  handoff_hob->EfiFreeMemoryBottom = (EFI_PHYSICAL_ADDRESS) (UINTN) hob_end;

  return hob;
}

/**
  Builds a HOB that describes a chunk of system memory.
**/
void build_resource_descriptor_hob(EFI_RESOURCE_TYPE resource_type, EFI_RESOURCE_ATTRIBUTE_TYPE resource_attribute, 
        EFI_PHYSICAL_ADDRESS physical_start, UINT64 bytes_number)
{
  EFI_HOB_RESOURCE_DESCRIPTOR  *hob;

  hob = create_hob(EFI_HOB_TYPE_RESOURCE_DESCRIPTOR, sizeof (EFI_HOB_RESOURCE_DESCRIPTOR));
  if (!hob) die(" error in build resource hob\n");

  hob->ResourceType      = resource_type;
  hob->ResourceAttribute = resource_attribute;
  hob->PhysicalStart     = physical_start;
  hob->ResourceLength    = bytes_number;
  return;
}

/**
  Returns the next instance of a HOB type from the starting HOB.
**/
static void *get_next_hob(UINT16 type, CONST void *hob_start)
{
  EFI_PEI_HOB_POINTERS  hob;

  if (!hob_start) die("Get next hob error\n");

  hob.Raw = (UINT8 *) hob_start;
  // Parse the HOB list until end of list or matching type is found.
  while (!END_OF_HOB_LIST (hob)) {
    if (hob.Header->HobType == type) {
      return hob.Raw;
    }
    hob.Raw = GET_NEXT_HOB (hob);
  }
  return NULL;
}

/**
  Returns the first instance of a HOB type among the whole HOB list.
**/
void *get_first_hob(UINT16 type)
{
  void *hob_start;

  hob_start = get_hob_list();
  return get_next_hob(type, hob_start);
}

/**
**/
static void *get_next_guid_hob(CONST EFI_GUID *guid, CONST void *hob_start)
{
  EFI_PEI_HOB_POINTERS  guid_hob;

  guid_hob.Raw = (UINT8 *) hob_start;
  printk(BIOS_DEBUG, "The guid_hob.Raw is %p\n", guid_hob.Raw);
  printk(BIOS_DEBUG, "The hob_start is %p\n", hob_start);
  while ((guid_hob.Raw = get_next_hob(EFI_HOB_TYPE_GUID_EXTENSION, guid_hob.Raw)) != NULL) {
    if (compare_guid(guid, &guid_hob.Guid->Name)) {
      break;
    }
    guid_hob.Raw = GET_NEXT_HOB(guid_hob);
  }
  return guid_hob.Raw;
}

/**
  This function searches the first instance of a HOB among the whole HOB list.
**/
void *get_first_guid_hob(CONST EFI_GUID *guid)
{
  void      *hob_start;

  hob_start = get_hob_list();
  return get_next_guid_hob(guid, hob_start);
}

/**
  Builds a GUID HOB with a certain data length.
**/
void *build_guid_hob(CONST EFI_GUID *guid, UINTN data_length)
{
  EFI_HOB_GUID_TYPE *hob;

  // Make sure that data length is not too long.
  if (data_length > (0xffff - sizeof (EFI_HOB_GUID_TYPE)))
	  die ("data length error");

  hob = create_hob(EFI_HOB_TYPE_GUID_EXTENSION, (UINT16) (sizeof (EFI_HOB_GUID_TYPE) + data_length));
  copy_guid(&hob->Name, guid);
  return hob + 1;
}

/**
  Builds a HOB for the CPU.
**/
void build_cpu_hob(UINT8 memory_space_size, UINT8 io_space_Size)
{
  EFI_HOB_CPU  *hob;

  hob = create_hob(EFI_HOB_TYPE_CPU, sizeof (EFI_HOB_CPU));

  hob->SizeOfMemorySpace = memory_space_size;
  hob->SizeOfIoSpace     = io_space_Size;

  // Zero the reserved space to match HOB spec
  memset (hob->Reserved, 0, sizeof (hob->Reserved));
  return;
}

/**
  Builds a HOB for the memory allocation.
**/
void build_memory_allocation_hob(EFI_PHYSICAL_ADDRESS base_address, UINT64 length, EFI_MEMORY_TYPE memory_type)
{
  EFI_HOB_MEMORY_ALLOCATION  *hob;

  if ((base_address & (EFI_PAGE_SIZE - 1)) || (length & (EFI_PAGE_SIZE - 1)))
	 die ("alignment");

  hob = create_hob(EFI_HOB_TYPE_MEMORY_ALLOCATION, sizeof (EFI_HOB_MEMORY_ALLOCATION));

  memset(&(hob->AllocDescriptor.Name), 0, sizeof (EFI_GUID));
  hob->AllocDescriptor.MemoryBaseAddress = base_address;
  hob->AllocDescriptor.MemoryLength      = length;
  hob->AllocDescriptor.MemoryType        = memory_type;
  // Zero the reserved space to match HOB spec
  memset(hob->AllocDescriptor.Reserved, 0, sizeof (hob->AllocDescriptor.Reserved));
  return;
}

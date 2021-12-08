/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HAND_OFF_BLOCK_H
#define HAND_OFF_BLOCK_H

#include <string.h>
#include <Uefi.h>
#include <Pi/PiBootMode.h>
#include <Pi/PiHob.h>
#include <Library/HobLib.h>
#include <program_loading.h>

#define SERIAL_INFO_GUID \
  {0xaa7e190d, 0xbe21, 0x4409, {0x8e, 0x67, 0xa2, 0xcd, 0xf, 0x61, 0xe1, 0x70}}

#define ACPI_TABLE_GUID \
  {0x9f9a9506, 0x5597, 0x4515, {0xba, 0xb6, 0x8b, 0xcd, 0xe7, 0x84, 0xba, 0x87}}

#define SMBIOS3_TABLE_GUID \
  {0x590a0d26, 0x06e5, 0x4d20, {0x8a, 0x82, 0x59, 0xea, 0x1b, 0x34, 0x98, 0x2d}}

#define EXTRA_DATA_GUID \
  {0x15a5baf6, 0x1c91, 0x467d, {0x9d, 0xfb, 0x31, 0x9d, 0x17, 0x8d, 0x4b, 0xb4}}

#define MEM_RANGE_COUNT(_rec) \
	  (((_rec)->size - sizeof(*(_rec))) / sizeof((_rec)->map[0]))

#define MEM_RANGE_PTR(_rec, _idx) \
	    (void *)(((UINT8 *) (_rec)) + sizeof(*(_rec)) \
          + (sizeof((_rec)->map[0]) * (_idx)))

typedef void \
        (*BL_MEM_INFO_CALLBACK) (struct lb_memory_range *range, void* para);

#define E820_RAM       1
#define E820_RESERVED  2
#define E820_ACPI      3
#define E820_NVS       4
#define E820_UNUSABLE  5
#define E820_DISABLED  6
#define E820_PMEM      7
#define E820_UNDEFINED 8

#pragma pack(1)
typedef struct {
  UINT32                          identifier;
  UINT32                          header_length;
  UINT16                          spec_revision;
  UINT8                           reserved[2];
  UINT32                          revision;
  UINT32                          attribute;
  UINT32                          capability;
  CHAR8                           producer_id[16];
  CHAR8                           image_id[16];
} universal_payload_info_header;

typedef struct {
  UINT8   revision;
  UINT8   reserved;
  UINT16  length;
} universal_payload_generic_header;

typedef struct {
  universal_payload_generic_header   header;
  EFI_PHYSICAL_ADDRESS               address;
} table_hob;

typedef struct {
  universal_payload_generic_header   header;
  BOOLEAN                            use_mmio;
  UINT8                              register_width;
  UINT32                             baud;
  EFI_PHYSICAL_ADDRESS               register_base;
} serial_port_info;

typedef struct {
  char                   identifier[16];
  EFI_PHYSICAL_ADDRESS   base;
  uint32_t               size;
} universal_payload_extra_data_entry;

typedef struct {
  universal_payload_generic_header   header;
  UINT32                             count;
  universal_payload_extra_data_entry entry[0];
} universal_payload_extra_data;
#pragma pack()

EFI_HOB_HANDOFF_INFO_TABLE *hob_table_init(void *memory_bottom, void *memory_top,
        void *free_memory_bottom, void *free_memory_top);
void build_memory_allocation_hob(EFI_PHYSICAL_ADDRESS base_address, UINT64 length,
		EFI_MEMORY_TYPE memory_type);
void build_resource_descriptor_hob(EFI_RESOURCE_TYPE resource_type, EFI_RESOURCE_ATTRIBUTE_TYPE resource_attribute, 
        EFI_PHYSICAL_ADDRESS physical_start, UINT64 bytes_number);
void build_cpu_hob(UINT8 memory_space_size, UINT8 io_space_Size);
void *get_first_hob(UINT16 type);
void *get_first_guid_hob(CONST EFI_GUID *guid);
void *build_guid_hob(CONST EFI_GUID *guid, UINTN data_length);

void* build_payload_hobs(struct cbfs_payload_segment *cbfssegs);

#endif /* PROGRAM_LOADING_H */

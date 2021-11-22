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

#define GET_GUID_HOB_DATA(HobStart) \
  (VOID *)(*(UINT8 **)&(HobStart) + sizeof (EFI_HOB_GUID_TYPE))

#pragma pack(1)
typedef struct {
  UINT8   revision;
  UINT8   reserved;
  UINT16  length;
} UNIVERSAL_PAYLOAD_GENERIC_HEADER;

typedef struct {
  UNIVERSAL_PAYLOAD_GENERIC_HEADER   header;
  EFI_PHYSICAL_ADDRESS               TableAddress;
} TABLE_HOB;

typedef struct {
  UNIVERSAL_PAYLOAD_GENERIC_HEADER   header;
  BOOLEAN                            UseMmio;
  UINT8                              RegisterWidth;
  UINT32                             BaudRate;
  EFI_PHYSICAL_ADDRESS               RegisterBase;
} SERIAL_PORT_INFO;

typedef struct {
  char                   identifier[16];
  EFI_PHYSICAL_ADDRESS   base;
  uint32_t               size;
} UNIVERSAL_PAYLOAD_EXTRA_DATA_ENTRY;

typedef struct {
  UNIVERSAL_PAYLOAD_GENERIC_HEADER   header;
  UINT32                             count;
  UNIVERSAL_PAYLOAD_EXTRA_DATA_ENTRY entry[0];
} UNIVERSAL_PAYLOAD_EXTRA_DATA;
#pragma pack()

EFI_HOB_HANDOFF_INFO_TABLE* hob_table_init(VOID *MemoryBegin, UINTN MemoryLength,
	VOID *EfiFreeMemoryBottom, VOID *EfiFreeMemoryTop);

void* build_payload_hobs (struct cbfs_payload_segment *cbfssegs);

static inline int CompareGuid(const EFI_GUID *guid1, const EFI_GUID *guid2)
{
	                return !memcmp(guid1, guid2, sizeof(EFI_GUID));
}

static inline EFI_GUID *CopyGuid(EFI_GUID *dest, const EFI_GUID *src)
{
	                return (EFI_GUID *)memcpy(dest, src, sizeof(EFI_GUID));
}

#endif /* PROGRAM_LOADING_H */

/* SPDX-License-Identifier: GPL-2.0-only */

#include <arch/hlt.h>
#include <console/console.h>
#include <string.h>
#include <commonlib/coreboot_tables.h>
#include <cbmem.h>
#include <hob.h>
#include <Guid/GraphicsInfoHob.h>
#include <commonlib/endian.h>

static UINT32 mTopOfLowerUsableDram = 0;

static void *find_cb_tag(struct lb_header *cbtable, UINT32 Tag)
{
  struct lb_record   *record;
  UINT8              *tmp_ptr;
  UINT8              *tag_ptr;
  UINTN              idx;

  tag_ptr = NULL;
  tmp_ptr = (UINT8 *)cbtable + cbtable->header_bytes;
  for (idx = 0; idx < cbtable->table_entries; idx++) {
    record = (struct lb_record *)tmp_ptr;
    if (record->tag == Tag) {
       tag_ptr = tmp_ptr;
       break;
    }
    tmp_ptr += record->size;
  }
  return tag_ptr;
}

static void build_gfx_info_hob(struct lb_header *cbtable)
{
  struct lb_framebuffer                 *lb_fb;
  EFI_GRAPHICS_OUTPUT_MODE_INFORMATION  *gfx_mode;
  EFI_PEI_GRAPHICS_INFO_HOB             *gfx_info;
  const EFI_GUID                        graphics_info_guid = EFI_PEI_GRAPHICS_INFO_HOB_GUID;

  lb_fb = find_cb_tag(cbtable, LB_TAG_FRAMEBUFFER);
  if (!lb_fb) {
    printk(BIOS_WARNING, "Fail to find LB_TAG_FRAMEBUFFER\n");
    return;
  }

  gfx_info = build_guid_hob(&graphics_info_guid, sizeof(*gfx_info));
  if (!gfx_info) {
    printk(BIOS_WARNING, "Fail to create gfx_info hob\n");
    return;
  }

  gfx_mode = &gfx_info->GraphicsMode;
  gfx_mode->Version              = 0;
  gfx_mode->HorizontalResolution = lb_fb->x_resolution;
  gfx_mode->VerticalResolution   = lb_fb->y_resolution;
  gfx_mode->PixelsPerScanLine    = (lb_fb->bytes_per_line << 3) / lb_fb->bits_per_pixel;
  if ((lb_fb->red_mask_pos == 0) && (lb_fb->green_mask_pos == 8) && (lb_fb->blue_mask_pos == 16)) {
        gfx_mode->PixelFormat = PixelRedGreenBlueReserved8BitPerColor;
  } else if ((lb_fb->blue_mask_pos == 0) && (lb_fb->green_mask_pos == 8) && (lb_fb->red_mask_pos == 16)) {
    gfx_mode->PixelFormat = PixelBlueGreenRedReserved8BitPerColor;
  }
  gfx_mode->PixelInformation.RedMask      = ((1 << lb_fb->red_mask_size)      - 1) << lb_fb->red_mask_pos;
  gfx_mode->PixelInformation.GreenMask    = ((1 << lb_fb->green_mask_size)    - 1) << lb_fb->green_mask_pos;
  gfx_mode->PixelInformation.BlueMask     = ((1 << lb_fb->blue_mask_size)     - 1) << lb_fb->blue_mask_pos;
  gfx_mode->PixelInformation.ReservedMask = ((1 << lb_fb->reserved_mask_size) - 1) << lb_fb->reserved_mask_pos;

  gfx_info->FrameBufferBase = lb_fb->physical_address;
  gfx_info->FrameBufferSize = lb_fb->bytes_per_line *  lb_fb->y_resolution;

  return;
}

static void build_serial_hob(struct lb_header *cbtable)
{
  struct lb_serial          *lbSerial;
  serial_port_info          *hob_serial;
  EFI_GUID                  serial_guid = SERIAL_INFO_GUID;

  lbSerial = find_cb_tag(cbtable, LB_TAG_SERIAL);
  if (!lbSerial) {
    printk(BIOS_WARNING, "Fail to find LB_TAG_SERIAL\n");
    return;
  }

  hob_serial = build_guid_hob(&serial_guid, sizeof(*hob_serial));
  if (!hob_serial) {
    printk(BIOS_WARNING, "Fail to create serial_info hob\n");
    return;
  }

  hob_serial->header.revision     = 1;
  hob_serial->header.length       = sizeof(serial_port_info);
  if (lbSerial->type == LB_SERIAL_TYPE_MEMORY_MAPPED)
     hob_serial->use_mmio    = TRUE;
  else
     hob_serial->use_mmio    = FALSE;
  hob_serial->register_width = (UINT8)lbSerial->regwidth;
  hob_serial->baud           = lbSerial->baud;
  hob_serial->register_base  = lbSerial->baseaddr;

  return;
}

static void build_acpi_hob(void)
{
  EFI_PHYSICAL_ADDRESS  acpi_base;
  table_hob            *acpi_hob;
  EFI_GUID              acpi_guid = ACPI_TABLE_GUID;

  acpi_base = (EFI_PHYSICAL_ADDRESS)(UINTN)cbmem_find(CBMEM_ID_ACPI);
  if (!acpi_base) {
    printk(BIOS_WARNING, "Fail to find CBMEM_ID_ACPI\n");
    return;
  }

  acpi_hob = build_guid_hob(&acpi_guid, sizeof (table_hob));
  if (!acpi_hob) {
    printk(BIOS_WARNING, "Fail to create acpi hob\n");
    return;
  }

  acpi_hob->header.revision = 1;
  acpi_hob->header.length   = sizeof(table_hob);
  acpi_hob->address    = acpi_base;
  return;
}

static void build_smbios_hob(void)
{
  EFI_PHYSICAL_ADDRESS     smbios_base;
  table_hob               *smbios_hob;
  EFI_GUID                 smbios_guid = SMBIOS3_TABLE_GUID;

  smbios_base = (EFI_PHYSICAL_ADDRESS)(UINTN)cbmem_find(CBMEM_ID_SMBIOS);
  if (!smbios_base) {
    printk(BIOS_WARNING, "Fail to find CBMEM_ID_SMBIOS\n");
    return;
  }

  smbios_hob = build_guid_hob(&smbios_guid, sizeof (table_hob));
  if (!smbios_hob) {
    printk(BIOS_WARNING, "Fail to create smbios hob\n");
    return;
  }

  smbios_hob->header.revision = 1;
  smbios_hob->header.length   = sizeof(table_hob);
  smbios_hob->address = smbios_base;
  return;
}

static void cbfs_decode_payload_segment(struct cbfs_payload_segment *segment,
		const struct cbfs_payload_segment *src)
{
	segment->type        = read_be32(&src->type);
	segment->compression = read_be32(&src->compression);
	segment->offset      = read_be32(&src->offset);
	segment->load_addr   = read_be64(&src->load_addr);
	segment->len         = read_be32(&src->len);
	segment->mem_len     = read_be32(&src->mem_len);
}

static void build_extra_data_hob(struct cbfs_payload_segment *cbfssegs)
{
  universal_payload_extra_data   *extra_data_hob;
  EFI_GUID                        extra_data_guid = EXTRA_DATA_GUID;
  struct cbfs_payload_segment    *seg,  segment, *first_upld_addr = NULL;
  universal_payload_info_header  *pld_info;
  int                             length;
  int                             extra_count = 0;
  int                             index;
  uint64_t                        payload_size;

  /* The Fv are between the upid_info segment and entry segments.
     upid_info segment is the last DATA type segment in the component*/
  for (seg = cbfssegs;; ++seg) {
    switch (read_be32(&seg->type)) {
    case PAYLOAD_SEGMENT_CODE:
      if (first_upld_addr)
        extra_count++;
      continue;
    case PAYLOAD_SEGMENT_DATA:
      first_upld_addr = seg + 1;
      extra_count = 0;
      pld_info = (universal_payload_info_header *)read_be32(&seg->load_addr);
      continue;
    case PAYLOAD_SEGMENT_ENTRY:
      break;
    default:
      break;
    }
    break;
  }

  length = sizeof (universal_payload_extra_data) + extra_count * sizeof (universal_payload_extra_data_entry);
  extra_data_hob = build_guid_hob(&extra_data_guid, length);
  if (!extra_data_hob) {
    printk(BIOS_WARNING, "Fail to create extra_data hob\n");
    return;
  }
  extra_data_hob->header.revision = 1;
  extra_data_hob->header.length   = length;
  extra_data_hob->count           = extra_count;
  if (extra_count != 0) {
    seg = first_upld_addr;
    printk(BIOS_DEBUG, "Loading %d upld from %p\n", extra_count, first_upld_addr);
    for (index = 0;index < extra_count; index++, seg++) {
      cbfs_decode_payload_segment(&segment, seg);
      extra_data_hob->entry[index].base = segment.load_addr;
      extra_data_hob->entry[index].size = segment.mem_len;
      strncpy(extra_data_hob->entry[index].identifier, "uefi_fv", sizeof (extra_data_hob->entry[0].identifier));
    }
    payload_size = segment.load_addr + segment.mem_len - 0x800000;
    payload_size = (payload_size + (EFI_PAGE_SIZE - 1)) & (~(EFI_PAGE_SIZE - 1));
    build_memory_allocation_hob(0x800000, payload_size, EfiBootServicesData);
  }
  return;
}

static void mem_info_callback_mmio(struct lb_memory_range *range, void* para)
{
  EFI_RESOURCE_TYPE            type;
  EFI_RESOURCE_ATTRIBUTE_TYPE  attribute;
  uint64_t base = unpack_lb64(range->start);
  uint64_t size = unpack_lb64(range->size);

  if (range->type == E820_RAM || range->type == E820_ACPI || range->type == E820_NVS) {
    return;
  }
  if (base < mTopOfLowerUsableDram) {
    //
    // It's in DRAM and thus must be reserved
    //
    type = EFI_RESOURCE_MEMORY_RESERVED;
  } else if ((base < 0x100000000ULL) && (base >= mTopOfLowerUsableDram)) {
    //
    // It's not in DRAM, must be MMIO
    //
    type = EFI_RESOURCE_MEMORY_MAPPED_IO;
  } else {
    type = EFI_RESOURCE_MEMORY_RESERVED;
  }
  attribute = EFI_RESOURCE_ATTRIBUTE_PRESENT |
             EFI_RESOURCE_ATTRIBUTE_INITIALIZED |
             EFI_RESOURCE_ATTRIBUTE_TESTED |
             EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE |
             EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE |
             EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE |
             EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE;

  build_resource_descriptor_hob(type, attribute, base, size);

  if (range->type == E820_UNUSABLE || range->type == E820_DISABLED) {
    build_memory_allocation_hob(base, size, EfiUnusableMemory);
  } else if (range->type == E820_PMEM) {
  }
    build_memory_allocation_hob(base, size, EfiPersistentMemory);
}

static void mem_info_callback(struct lb_memory_range *range, void* para)
{
  EFI_RESOURCE_TYPE            type;
  EFI_RESOURCE_ATTRIBUTE_TYPE  attribute;
  uint64_t base = unpack_lb64(range->start);
  uint64_t size = unpack_lb64(range->size);

  type = EFI_RESOURCE_SYSTEM_MEMORY;
  if ((range->type != E820_RAM) && (range->type != E820_ACPI) && (range->type != E820_NVS)) {
    return;
  }

  attribute = EFI_RESOURCE_ATTRIBUTE_PRESENT | \
             EFI_RESOURCE_ATTRIBUTE_INITIALIZED | \
             EFI_RESOURCE_ATTRIBUTE_TESTED | \
             EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE | \
             EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE | \
             EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE | \
             EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE;

  build_resource_descriptor_hob(type, attribute, base, size);
  if (range->type == E820_ACPI) {
    build_memory_allocation_hob(base, size, EfiACPIReclaimMemory);
  } else if (range->type == E820_NVS) {
    build_memory_allocation_hob(base, size, EfiACPIMemoryNVS);
  }
}

static void find_tolud_callback(struct lb_memory_range *range, void* para)
{
  uint64_t base = unpack_lb64(range->start);
  uint64_t size = unpack_lb64(range->size);
  if ((range->type == E820_UNUSABLE) || (range->type == E820_DISABLED) ||
    (range->type == E820_PMEM)) {
    return;
  }
  /* Skip resources above 4GiB */
  if ((base + size) > 0x100000000ULL) {
    return;
  }

  if ((range->type == E820_RAM) || (range->type == E820_ACPI) || (range->type == E820_NVS)) {
    //
    // It's usable DRAM. Update TOLUD.
    //
    if (mTopOfLowerUsableDram < (base + size)) {
      mTopOfLowerUsableDram = (UINT32)(base + size);
    }
  } else {
    //
    // It might be 'reserved DRAM' or 'MMIO'.
    //
    // If it touches usable DRAM at Base assume it's DRAM as well,
    // as it could be bootloader installed tables, TSEG, GTT, ...
    //
    if (mTopOfLowerUsableDram == base) {
      mTopOfLowerUsableDram = (UINT32)(base + size);
    }
  }
  return;
}

static void parse_memory_range(BL_MEM_INFO_CALLBACK range_info_callback, struct lb_header *cbtable)
{
  struct lb_memory         *rec;
  struct lb_memory_range   *range;
  int                       index;

  rec = (struct lb_memory *)find_cb_tag(cbtable, LB_TAG_MEMORY);
  if (!rec) {
    printk(BIOS_WARNING, "Fail to find LB_TAG_MEMORY\n");
    return;
  }

  for (index = 0; index < MEM_RANGE_COUNT(rec); index++) {
    range = MEM_RANGE_PTR(rec, index);
    range_info_callback(range, NULL);
  }
  return;
}

static void conver_coreboot_tables_to_hob(void)
{
  struct lb_header *cbtable;

  cbtable = (struct lb_header *)cbmem_find(CBMEM_ID_CBTABLE);
  if (!cbtable) {
    printk(BIOS_ERR, "No coreboot table found!\n");
    return;
  }
  printk(BIOS_DEBUG, "Successfully found the CBTABLE header at %p\n", cbtable);

  parse_memory_range(find_tolud_callback, cbtable);
  parse_memory_range(mem_info_callback, cbtable);
  build_serial_hob(cbtable);
  build_gfx_info_hob(cbtable);
  build_acpi_hob();
  build_smbios_hob();
  parse_memory_range(mem_info_callback_mmio, cbtable);
}

static void build_generic_hob(void)
{
  EFI_RESOURCE_ATTRIBUTE_TYPE  attribute;

  // Hard code for now
  build_cpu_hob(36, 16);

  attribute = EFI_RESOURCE_ATTRIBUTE_PRESENT | EFI_RESOURCE_ATTRIBUTE_INITIALIZED |\
              EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE | EFI_RESOURCE_ATTRIBUTE_TESTED;
  build_resource_descriptor_hob(EFI_RESOURCE_MEMORY_MAPPED_IO, attribute, 0xFEC80000, SIZE_512KB);
  build_memory_allocation_hob(0xFEC80000, SIZE_512KB, EfiMemoryMappedIO);
}

void* build_payload_hobs(struct cbfs_payload_segment *cbfssegs)
{
  EFI_HOB_HANDOFF_INFO_TABLE    *hob_table;
  void   *hob_base;

  hob_base = cbmem_add(CBMEM_ID_HOB_POINTER, 0x4000);
  if (!hob_base) {
    printk(BIOS_ERR, "Could not add hob_base in CBMEM\n");
    return NULL;
  }
  hob_table = hob_table_init(hob_base, (u8 *)hob_base + 0x4000, hob_base, (u8 *)hob_base + 0x4000);
  printk(BIOS_DEBUG, "Create hob list at %p\n", hob_table);

  build_extra_data_hob(cbfssegs);
  conver_coreboot_tables_to_hob();
  build_generic_hob();
  
  return (void *)hob_table;
}

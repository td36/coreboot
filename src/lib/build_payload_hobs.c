/* SPDX-License-Identifier: GPL-2.0-only */

#include <arch/hlt.h>
#include <console/console.h>
#include <string.h>
#include <commonlib/coreboot_tables.h>
#include <cbmem.h>
#include <hob.h>
#include <Guid/GraphicsInfoHob.h>
#include <commonlib/endian.h>

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

  gfx_info = BuildGuidHob(&graphics_info_guid, sizeof(*gfx_info));
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
  SERIAL_PORT_INFO          *hob_serial;
  EFI_GUID                  serial_guid = SERIAL_INFO_GUID;

  lbSerial = find_cb_tag(cbtable, LB_TAG_SERIAL);
  if (!lbSerial) {
    printk(BIOS_WARNING, "Fail to find LB_TAG_SERIAL\n");
    return;
  }

  hob_serial = BuildGuidHob(&serial_guid, sizeof(*hob_serial));
  if (!hob_serial) {
    printk(BIOS_WARNING, "Fail to create serial_info hob\n");
    return;
  }

  hob_serial->header.revision     = 1;
  hob_serial->header.length       = sizeof(SERIAL_PORT_INFO);
  if (lbSerial->type == LB_SERIAL_TYPE_MEMORY_MAPPED)
     hob_serial->UseMmio    = TRUE;
  else
     hob_serial->UseMmio    = FALSE;
  hob_serial->RegisterWidth = (UINT8)lbSerial->regwidth;
  hob_serial->BaudRate      = lbSerial->baud;
  hob_serial->RegisterBase  = lbSerial->baseaddr;

  return;
}

static void build_acpi_hob(void)
{
  EFI_PHYSICAL_ADDRESS  acpi_base;
  TABLE_HOB            *acpi_hob;
  EFI_GUID              acpi_guid = ACPI_TABLE_GUID;

  acpi_base = (EFI_PHYSICAL_ADDRESS)(UINTN)cbmem_find(CBMEM_ID_ACPI);
  if (!acpi_base) {
    printk(BIOS_WARNING, "Fail to find CBMEM_ID_ACPI\n");
    return;
  }

  acpi_hob = BuildGuidHob(&acpi_guid, sizeof (TABLE_HOB));
  if (!acpi_hob) {
    printk(BIOS_WARNING, "Fail to create acpi hob\n");
    return;
  }

  acpi_hob->header.revision = 1;
  acpi_hob->header.length   = sizeof(TABLE_HOB);
  acpi_hob->TableAddress    = acpi_base;
  return;
}

static void build_smbios_hob(void)
{
  EFI_PHYSICAL_ADDRESS     smbios_base;
  TABLE_HOB               *smbios_hob;
  EFI_GUID                 smbios_guid = SMBIOS3_TABLE_GUID;

  smbios_base = (EFI_PHYSICAL_ADDRESS)(UINTN)cbmem_find(CBMEM_ID_SMBIOS);
  if (!smbios_base) {
    printk(BIOS_WARNING, "Fail to find CBMEM_ID_SMBIOS\n");
    return;
  }

  smbios_hob = BuildGuidHob(&smbios_guid, sizeof (TABLE_HOB));
  if (!smbios_hob) {
    printk(BIOS_WARNING, "Fail to create smbios hob\n");
    return;
  }

  smbios_hob->header.revision = 1;
  smbios_hob->header.length   = sizeof(TABLE_HOB);
  smbios_hob->TableAddress = smbios_base;
  return;
}


static void build_memory_resource_hob(struct lb_memory_range *range)
{
  EFI_PHYSICAL_ADDRESS         base;
  EFI_RESOURCE_TYPE            type;
  uint32_t                     size;
  EFI_RESOURCE_ATTRIBUTE_TYPE  attribute;

  type = (range->type == 1) ? EFI_RESOURCE_SYSTEM_MEMORY : EFI_RESOURCE_MEMORY_RESERVED;
  base = unpack_lb64(range->start);
  size = unpack_lb64(range->size);

  attribute = EFI_RESOURCE_ATTRIBUTE_PRESENT | \
             EFI_RESOURCE_ATTRIBUTE_INITIALIZED | \
             EFI_RESOURCE_ATTRIBUTE_TESTED | \
             EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE | \
             EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE | \
             EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE | \
             EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE;

  if (base >= BASE_4GB ) {
     attribute &= ~EFI_RESOURCE_ATTRIBUTE_TESTED;
  }

  BuildResourceDescriptorHob(type, attribute, (EFI_PHYSICAL_ADDRESS)base, size);
  return;
}


static void build_memory_hobs(struct lb_header *cbtable)
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
    build_memory_resource_hob(range);
  }
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
  UNIVERSAL_PAYLOAD_EXTRA_DATA   *extra_data_hob;
  EFI_GUID                        extra_data_guid = EXTRA_DATA_GUID;
  struct cbfs_payload_segment    *seg, *entry_seg, segment, *first_upld_addr = NULL;
  UNIVERSAL_PAYLOAD_INFO_HEADER  *pld_info;
  int                             length;
  int                             extra_count = 0;
  int                             index;

  /* The Fv are between the upid_info and entry segments
     upid_info segment is the last DATA type segment in the component*/
  for (seg = cbfssegs;; ++seg) {
    if (read_be32(&seg->type) == PAYLOAD_SEGMENT_ENTRY) {
      entry_seg = seg;
      break;
    }
  }
  for (seg = entry_seg - 1;seg >= cbfssegs; --seg) {
    if (read_be32(&seg->type) == PAYLOAD_SEGMENT_DATA) {
      first_upld_addr = seg +1;
      pld_info = (UNIVERSAL_PAYLOAD_INFO_HEADER *)read_be32(&seg->load_addr);
      break;
    }
    extra_count++;
  }

  length = sizeof (UNIVERSAL_PAYLOAD_EXTRA_DATA) + extra_count * sizeof (UNIVERSAL_PAYLOAD_EXTRA_DATA_ENTRY);
  extra_data_hob = BuildGuidHob (&extra_data_guid, length);
  if (!extra_data_hob) {
    printk(BIOS_WARNING, "Fail to create extra_data hob\n");
    return;
  }
  extra_data_hob->header.revision = 1;
  extra_data_hob->header.length   = length;
  extra_data_hob->count           = extra_count;
  if (extra_count != 0) {
    printk(BIOS_DEBUG, "%d upld are found\n", extra_count);
    seg = first_upld_addr;
    for (index = 0;index < extra_count; index++, seg++) {
      cbfs_decode_payload_segment(&segment, seg);
      extra_data_hob->entry[index].base   = segment.load_addr;
      extra_data_hob->entry[index].size   = segment.mem_len;
      strncpy(extra_data_hob->entry[index].identifier, "uefi_fv", sizeof (extra_data_hob->entry[0].identifier));
    }
  }
  return;
}


/* It will build HOBs based on information from bootloaders.*/
void* build_payload_hobs(struct cbfs_payload_segment *cbfssegs)
{
  EFI_HOB_HANDOFF_INFO_TABLE       *hob_table;
  void                             *hob_base;
  struct lb_header                 *cbtable;
  EFI_RESOURCE_ATTRIBUTE_TYPE      attribute;

  hob_base = cbmem_add(CBMEM_ID_HOB_POINTER, 0x4000);
  if (!hob_base) {
    printk(BIOS_ERR, "Could not add hob_base in CBMEM\n");
    return NULL;
  }
  hob_table = hob_table_init(hob_base, 0x4000, hob_base, (u8 *)hob_base + 0x4000);
  
  cbtable = (struct lb_header *)cbmem_find(CBMEM_ID_CBTABLE);
  if (!cbtable) {
    printk(BIOS_ERR, "FIT: No coreboot table found!\n");
    return NULL;
  }
  printk(BIOS_DEBUG, "the CBTABLE header is %p\n", cbtable);

  build_serial_hob(cbtable);
  build_memory_hobs(cbtable);
  build_extra_data_hob(cbfssegs);
  build_gfx_info_hob(cbtable);
  build_acpi_hob();
  build_smbios_hob();
  // Hard code for now
  BuildCpuHob(36, 16);

  // Report Local APIC range
  attribute = EFI_RESOURCE_ATTRIBUTE_PRESENT | EFI_RESOURCE_ATTRIBUTE_INITIALIZED |\
              EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE | EFI_RESOURCE_ATTRIBUTE_TESTED;
  BuildResourceDescriptorHob(EFI_RESOURCE_MEMORY_MAPPED_IO, attribute, 0xFEC80000, SIZE_512KB);
  BuildMemoryAllocationHob(0xFEC80000, SIZE_512KB, EfiMemoryMappedIO);

  printk(BIOS_DEBUG, "The Hoblist is 0x%x\n", (UINTN)hob_table);
  printk(BIOS_DEBUG, "the EfiMemoryTop is 0x%llx the EfiMemoryBottom is 0x%llx, EfiFreeMemoryTop is 0x%llx, EfiFreeMemoryBottom is 0x%llx \n", 
     hob_table->EfiMemoryTop, hob_table->EfiMemoryBottom, hob_table->EfiFreeMemoryTop, hob_table->EfiFreeMemoryBottom);
  
  return (void *)hob_table;
}

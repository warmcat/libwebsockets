/*
 * GENERATED FILE - DO NOT EDIT
 * Copyright (c) 2008-2013 Code Red Technologies Ltd,
 * Copyright 2015, 2018-2019 NXP
 * (c) NXP Semiconductors 2013-2021
 * Generated linker script file for MIMXRT595S
 * Created from memory.ldt by FMCreateLinkMemory
 * Using Freemarker v2.3.30
 * MCUXpresso IDE v11.4.1 [Build 6260] [2021-09-15] on Oct 24, 2021, 10:02:43 AM
 */

MEMORY
{
  /* Define each memory region */
  QSPI_FLASH (rx) : ORIGIN = 0x8000000, LENGTH = 0x800000 /* 8M bytes (alias Flash) */  
  SRAM (rwx) : ORIGIN = 0x80000, LENGTH = 0x280000 /* 2560K bytes (alias RAM) */  
  USB_RAM (rwx) : ORIGIN = 0x40140000, LENGTH = 0x4000 /* 16K bytes (alias RAM2) */  
}

  /* Define a symbol for the top of each memory region */
  __base_QSPI_FLASH = 0x8000000  ; /* QSPI_FLASH */  
  __base_Flash = 0x8000000 ; /* Flash */  
  __top_QSPI_FLASH = 0x8000000 + 0x800000 ; /* 8M bytes */  
  __top_Flash = 0x8000000 + 0x800000 ; /* 8M bytes */  
  __base_SRAM = 0x80000  ; /* SRAM */  
  __base_RAM = 0x80000 ; /* RAM */  
  __top_SRAM = 0x80000 + 0x280000 ; /* 2560K bytes */  
  __top_RAM = 0x80000 + 0x280000 ; /* 2560K bytes */  
  __base_USB_RAM = 0x40140000  ; /* USB_RAM */  
  __base_RAM2 = 0x40140000 ; /* RAM2 */  
  __top_USB_RAM = 0x40140000 + 0x4000 ; /* 16K bytes */  
  __top_RAM2 = 0x40140000 + 0x4000 ; /* 16K bytes */  

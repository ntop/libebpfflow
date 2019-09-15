/* pcapio.h
 * Declarations of our own routines for writing libpcap files.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Derived from code in the Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Writing pcap files */

/** Write the file header to a dump file.
   Returns TRUE on success, FALSE on failure.
   Sets "*err" to an error code, or 0 for a short write, on failure*/
extern u_int8_t
libpcap_write_file_header(FILE* pfile, int linktype, int snaplen,
                          u_int8_t ts_nsecs, u_int64_t *bytes_written, int *err);

/** Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
extern u_int8_t
libpcap_write_packet(FILE* pfile,
                     time_t sec, u_int32_t usec,
                     u_int32_t caplen, u_int32_t len,
                     const u_int8_t *pd,
                     u_int64_t *bytes_written, int *err);

/* Writing pcapng files */

/* Write a pre-formatted pcapng block */
extern u_int8_t
pcapng_write_block(FILE* pfile,
                  const u_int8_t *data,
                  u_int32_t block_total_length,
                  u_int64_t *bytes_written,
                  int *err);

/** Write a section header block (SHB)
 *
 */
extern u_int8_t
pcapng_write_section_header_block(FILE* pfile,  /**< Write information */
                                  const char *comment,  /**< Comment on the section, Optinon 1 opt_comment
                                                         * A UTF-8 string containing a comment that is associated to the current block.
                                                         */
                                  const char *hw,       /**< HW, Optinon 2 shb_hardware
                                                         * An UTF-8 string containing the description of the hardware  used to create this section.
                                                         */
                                  const char *os,       /**< Operating system name, Optinon 3 shb_os
                                                         * An UTF-8 string containing the name of the operating system used to create this section.
                                                         */
                                  const char *appname,  /**< Application name, Optinon 4 shb_userappl
                                                         * An UTF-8 string containing the name of the application  used to create this section.
                                                         */
                                  u_int64_t section_length, /**< Length of section */
                                  u_int64_t *bytes_written, /**< Number of written bytes */
                                  int *err /**< Error type */
                                  );

extern u_int8_t
pcapng_write_interface_description_block(FILE* pfile,
                                         const char *comment,  /* OPT_COMMENT           1 */
                                         const char *name,     /* IDB_NAME              2 */
                                         const char *descr,    /* IDB_DESCRIPTION       3 */
                                         const char *filter,   /* IDB_FILTER           11 */
                                         const char *os,       /* IDB_OS               12 */
                                         int link_type,
                                         int snap_len,
                                         u_int64_t *bytes_written,
                                         u_int64_t if_speed,     /* IDB_IF_SPEED          8 */
                                         u_int8_t tsresol,       /* IDB_TSRESOL           9 */
                                         int *err);

extern u_int8_t
pcapng_write_interface_statistics_block(FILE* pfile,
                                        u_int32_t interface_id,
                                        u_int64_t *bytes_written,
                                        const char *comment,   /* OPT_COMMENT           1 */
                                        u_int64_t isb_starttime, /* ISB_STARTTIME         2 */
                                        u_int64_t isb_endtime,   /* ISB_ENDTIME           3 */
                                        u_int64_t isb_ifrecv,    /* ISB_IFRECV            4 */
                                        u_int64_t isb_ifdrop,    /* ISB_IFDROP            5 */
                                        int *err);

extern u_int8_t
pcapng_write_enhanced_packet_block(FILE* pfile,
                                   const char *comment,
                                   time_t sec, u_int32_t usec,
                                   u_int32_t caplen, u_int32_t len,
                                   u_int32_t interface_id,
                                   u_int32_t ts_mul,
                                   const u_int8_t *pd,
                                   u_int32_t flags,
                                   u_int64_t *bytes_written,
                                   int *err);

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

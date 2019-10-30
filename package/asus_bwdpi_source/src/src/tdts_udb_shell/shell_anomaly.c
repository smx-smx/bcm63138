/*
 * Copyright 2014 Trend Micro Incorporated
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software without 
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT 
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 */
#include <linux/types.h>

#include "udb/tdts_udb_shell.h"

extern int tdts_shell_flood_record(
	void *void_ptr,
	unsigned record_max,
	flood_spec_t *spec,
	pkt_info_t *pkt);
extern void tdts_shell_flood_record_output_and_init(
	void *void_ptr,
	unsigned record_max,
	uint32_t signature_id,
	uint16_t flood_type,
	flood_log_cb log_cb);
extern int tdts_shell_flood_mem_init(
	void *void_ptr,
	unsigned mem_size,
	unsigned record_max);

int udb_shell_anomaly_init(void)
{
	static udb_anomaly_ops_t udb_anomaly_ops = 
	{
		tdts_shell_flood_record
		, tdts_shell_flood_record_output_and_init
		, tdts_shell_flood_mem_init
#if TMCFG_E_CORE_PORT_SCAN_DETECTION
		, tdts_shell_port_scan_context_alloc
		, tdts_shell_port_scan_context_dealloc
#else
		, NULL, NULL
#endif
	};

	return udb_core_anomaly_init(&udb_anomaly_ops);
}
EXPORT_SYMBOL(udb_shell_anomaly_init);

void udb_shell_anomaly_exit(void)
{
	udb_core_anomaly_exit();
}
EXPORT_SYMBOL(udb_shell_anomaly_exit);


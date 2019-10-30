/*
	shared_api.c for TrendMicro DPI engine usage
	- all DPI function control and service control
*/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>

#include "bwdpi.h"

enum wan_unit_e {
	WAN_UNIT_NONE=-1,
	WAN_UNIT_FIRST=0,
#if defined(RTCONFIG_DUALWAN) || defined(RTCONFIG_USB_MODEM)
	WAN_UNIT_SECOND,
#endif
	WAN_UNIT_MAX
};

int send_loop(struct request_rec *r, char *buf, int size, char *func)
{
	int	nbytes, len = size,  ret=0;

	while (len > 0) {
#ifdef CONFIG_HTTPD_HTTPS_SUPPORT
		if (r->ishttps) {
			nbytes = len;
			ret = as_write(r->ssrv, (unsigned char *)buf, nbytes);
			if (ret <= 0)
			{
				return -1;
			}
		} else
#endif

		{
			nbytes = send(r->sd, buf, len, 0);
			if (nbytes < 0) {
				char tbuf[512];

				if (errno == EAGAIN || errno == EWOULDBLOCK)
					continue;
				else if (errno == ECONNRESET)
				{
					snprintf(tbuf, sizeof(tbuf)-1, "%s: failed, sock=%d, code=%d[Reset by peer, ECONNRESET], len=%d\n",
							func, r->sd, errno, len);
				}
				else if (errno == EPIPE)
				{
					snprintf(tbuf, sizeof(tbuf)-1, "%s: failed, sock=%d, code=%d[Pipe broken, EPIPE], len=%d\n",
							func, r->sd, errno, len);
				}

				tbuf[sizeof(tbuf)-1] = '\0';
				log_error(tbuf);

				return -1;
			}
		}

		len -= nbytes;
		buf += nbytes;
	}

	return size;
}

/*
 * so_flush(): send out whole data in outgoing buffer.
 * Return Value
 *      On success, return 0
 *      On error, return -1
 */
int so_flush(register struct request_rec *r)
{
	if (send_loop(r, r->out_buf, r->out_pos, "so_flush()") < 0)
		return -1;

	r->out_pos = 0;
	return 0;
}

void log_error(char *err) 
{
	printf("[%lu] %s\n", (unsigned long)pthread_self(), err);
}

/*
 * so_printf(): append a formatted string to the outgoing buffer. if free space
 *              of the buffer is to small to storing this string, flush out the
 *              old data to socket first.
 *
 * History:
 *      Add support for processing SSI documents locally.
 *
 * Return Value
 *      On success, return the number of bytes sent
 *      On error, return -1
 */
int so_printf(register struct request_rec *r, const char *fmt, ...)
{
	char buffer[SOPRINTFBUFSIZE*2];
	va_list argptr;
	int nbytes;


	va_start(argptr, fmt);
	nbytes = vsnprintf(buffer, sizeof(buffer), fmt, argptr);
	va_end(argptr);

	if (r->out_pos + nbytes > IOBUFSIZE)
		if (so_flush(r) == -1)
			goto __failed;

	memcpy((void *)(r->out_buf + r->out_pos), (void *)buffer, nbytes);
	r->out_pos += nbytes;
	if (r->out_pos == IOBUFSIZE)
		if (so_flush(r) == -1)
			goto __failed;

	return nbytes;

__failed:
	log_error("so_printf");
	r->out_pos = 0;

	return -1;
}
#if 0
int pids(char *appname)
{
	pid_t *pidList;
	pid_t *pl;
	int count = 0;

	pidList = find_pid_by_name(appname);
	for (pl = pidList; *pl; pl++) {
		count++;
	}
	free(pidList);

	if (count)
		return 1;
	else
		return 0;
}
#endif

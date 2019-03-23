/*
 * Copyright (c) 2019 qianfan Zhao <qianfanguijin@163.com>
 * License: GPLv3
 *
 * Compile:
 * gcc main.c -Wall -g -D SERIAL -o serial
 * gcc main.c -Wall -g -D PPP_SNIFFER -o ppp_sniffer
 *
 * Run:
 * Capture serial port data by using `serial` tool:
 * If you use FT2232H usb to serial port adapter, don't forget set latery:
 * $ echo 2 > /sys/bus/usb-serial/devices/ttyUSB0/latency_timer
 * $ echo 2 > /sys/bus/usb-serial/devices/ttyUSB1/latency_timer
 * $ serial /dev/ttyUSB0 /dev/ttyUSB1 > serial.log
 *
 * Sniffer PPP packets from serial log, and write them in hexdump format.
 * $ ppp_sniffer -w serial.log > ppp.log
 *
 * Convent ppp.log to wireshark pcapng format:
 * $ text2pcap -t "%Y-%m-%d %H:%M:%S." -n -D -l 9 ppp.log ppp.pcapng
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#define __USE_GNU /* for memmem */
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <errno.h>
#include <sched.h>

/*
 * Print binary data in hexdump format.
 * 41 54 2B 43 4D 55 58 3D  30 2C 30 2C 35 0D 0D 0A | AT+CMUX=0,0,5... |
 * 4F 4B 0D 0A                                      | OK..             |
 */
static void hexdump(FILE *fp, unsigned char *buf, int size, int with_ascii)
{
	#define min(a, b) ((a) < (b) ? (a) : (b))
	int count = 0;


	while (count < size) {
		int bytes = min(16, size - count);
		fprintf(fp, "%04X ", count);

		for (int i = 0; i < 16; i++) {
			if (i < bytes)
				fprintf(fp, "%02X ", buf[count + i]);
			else
				fprintf(fp, "   ");

			if (i == 7)
				fprintf(fp, " ");
		}

		if (with_ascii) {
			fprintf(fp, "| ");
			for (int i = 0; i < 16; i++) {
				unsigned char c = buf[count + i];
				if (i < bytes && isprint(c))
					fprintf(fp, "%c", c);
				else
					fprintf(fp, "%c",
						i < bytes ? '.' : ' ');
			}
			fprintf(fp, " |");
		}

		count += bytes;
		if (count % 16 == 0) {
			fprintf(fp, "\n");
		}
	}

	if (count % 16 != 0)
		fprintf(fp, "\n");
	fflush(fp);
}

/*
 * We support two way to capture rx/tx data:
 * 1. Use only one usb to serial port device, wire-and two signal
 *    by using two diode(this is the easiest way but can't detect
 *    the packet is come from modem or host). This is the default
 *    mode.
 * 2. Use two usb to serial port device such as FT2232H, this need
 *    a specify hardware, and the advantage is can detect the
 *    direction of the data, but sometimes this way can't detect
 *    which packet come first.
 *
 * The FTDI collects data from the slave device, transmitting it to
 * the host when either A) 62 bytes are received, or B) the timeout
 * interval has elapsed and the buffer contains at least 1 byte.
 * Setting this value to a small number can dramatically improve
 * performance for applications which send small packets,
 * since the default value is 16ms.
 * $ echo 2 > /sys/bus/usb-serial/devices/ttyUSB0/latency_timer
 * $ echo 2 > /sys/bus/usb-serial/devices/ttyUSB1/latency_timer
 */
#define MAX_PORT			2

/*
 * Every times we received data from serial port, add a specify header
 * and send to next.
 */
struct header {
	int			chn;
	int			len;
	struct timeval		tv;
};

static int read_header(FILE *where, struct header *header)
{
	unsigned char *buf = (unsigned char *)header;
	int ret, cnt = 0;

	while (cnt < sizeof(*header)) {
		ret = fread(buf + cnt, 1, sizeof(*header) - cnt, where);
		if (ret < 0) {
			fprintf(stderr, "Read header failed. exit\n");
			exit(-1);
		} else if (ret == 0) {
			fclose(where);
			exit(0);
		}
		cnt += ret;
	}

	if (header->chn >= MAX_PORT) {
		fprintf(stderr, "Invalid header, hexdump:\n");
		hexdump(stderr, buf, sizeof(*header), 0);
		exit(-1);
	}

	return 0;
}

static int read_stream(FILE *where, struct header *header,
		       unsigned char *buf, int size)
{
	int ret, cnt = 0;

	read_header(where, header);
	while (cnt < header->len) {
		ret = fread(buf + cnt, 1, header->len - cnt, where);
		if (ret < 0) {
			fprintf(stderr, "Read %d bytes data failed\n",
				header->len);
			exit(-1);
		} else if (ret == 0) {
			fclose(where);
			return 0;
		}
		cnt += ret;
	}

	return 0;
}

/*
 * The default mode if without '-h' is write binary data to stdout,
 * '-h' will convent binary data to hex mode first and then write to stdout.
 * '-n' can append usecond after time string.
 * '-a' can append ascii after hexdump.
 * '-l' can append packet length after hexdump.
 * '-d' can append direction after hexdump(CHN0 is output, 1 is input).
 * Another param '-w' can disable 'nald' flags, write data in hexdump mode.
 * (this is the wireshark needed. Can import this hexdump data to wireshark:
 *  File -> Import from Hex Dump -> Select file, timefmt: "%Y-%m-%d %H:%M:%S."
 *  select PPP protocol).
 */
static int hexmode = 0;
static int h_with_ns = 0, h_with_dir = 0, h_with_len = 0, h_with_ascii = 0;

/*
 * Set flag based on opt in getopt loops.
 */
#define HEXDUMP_OPTS				"hnald"

#define CASE_OPT_SET_FLAG(opt, flag)		\
	case opt:				\
		flag = 1;			\
		break

#define CASE_HEXDUMP_FLAGS			\
	CASE_OPT_SET_FLAG('h', hexmode);	\
	CASE_OPT_SET_FLAG('n', h_with_ns);	\
	CASE_OPT_SET_FLAG('a', h_with_ascii);	\
	CASE_OPT_SET_FLAG('l', h_with_len);	\
	CASE_OPT_SET_FLAG('d', h_with_dir)

static void write_data_stream_header(struct header *header)
{
	if (hexmode) {
		char tstring[64], cvt_fmt[64] = {0};

		struct tm *ptm = localtime(&header->tv.tv_sec);
		strftime(tstring, sizeof(tstring), "%Y-%m-%d %H:%M:%S", ptm);

		if (h_with_dir)
			strcat(cvt_fmt, "%c ");			/* Direction */
		strcat(cvt_fmt, "%s");				/* Day and time */

		if (h_with_ns)
			strcat(cvt_fmt, ".%09ld");	/* nanosecond */
		if (h_with_len)
			strcat(cvt_fmt, " - %d");	/* data length */

		strcat(cvt_fmt, "\n");
		fprintf(stdout, cvt_fmt, header->chn ? 'I' : 'O',
			tstring, header->tv.tv_usec * 1000,
			header->chn, header->len);
	} else fwrite(header, 1, sizeof(*header), stdout);
}

static void write_data_stream(struct header *header, unsigned char *buffer)
{
	write_data_stream_header(header);

	if (hexmode)
		hexdump(stdout, buffer, header->len, h_with_ascii);
	else fwrite(buffer, 1, header->len, stdout);
}

#ifdef SERIAL
/*
 * Connect to a serial port.
 */
static int serial_connect(const char* portname, int baudrate)
{
	struct termios options;
	int fd;

	if ((fd = open(portname, O_RDONLY | O_NOCTTY)) < 0) {
		fprintf(stderr, "can't connect to %s\n", portname);
	} else {
		tcgetattr(fd, &options);
		cfsetispeed(&options, B115200);
		cfsetospeed(&options, B115200);
		cfmakeraw(&options);
		if(tcsetattr(fd, TCSANOW, &options) < 0)
		{
			fprintf(stderr, "can't set serial port options\n");
			close(fd);
			fd = -1;
		}
		tcflush(fd, TCIFLUSH);
	}

	return fd;
}

static void serial_close(int fd)
{
	close(fd);
}

static int process_poll_event(struct pollfd *pfd, int channel)
{
	unsigned char buffer[4096];

	if(pfd->revents & POLLIN) {
		int bytes = read(pfd->fd, buffer, sizeof(buffer));
		if (bytes < 0 && errno != EINTR) {
			return -1;
		} else if (bytes > 0) {
			struct header header;

			gettimeofday(&header.tv, NULL);
			header.chn = channel;
			header.len = bytes;
			write_data_stream(&header, buffer);
		}
	}

	return pfd->events & POLLERR ? -1 : 0;
}

/*
 * Read data from file(not serial port) and dump them.
 */
static int serial_dump_record_file(const char *file)
{
	FILE *fp = fopen(file, "rb");
	unsigned char buf[4096];
	struct header h;

	if (!fp) {
		fprintf(stderr, "Can't read from %s, exit\n", file);
		return -1;
	}

	while (!read_stream(fp, &h, buf, sizeof(buf)))
		write_data_stream(&h, buf);

	return 0;
}

/*
 * Press Ctrl+C to exit.
 */
static volatile int done = 0;

static void terminate(int sig)
{
	done = 1;
}

int main(int argc, char* argv[])
{
	const char *serialport[MAX_PORT] = { "/dev/ttyUSB0", "/dev/ttyUSB1" };
	int baud = 115200, port_num = 1, serial_fd[MAX_PORT] = { 0, 0 };
	const char *read_from_file = NULL;
	int opt;

	while ((opt = getopt(argc, argv, HEXDUMP_OPTS "b:f:")) != -1) {
		switch (opt) {
		CASE_HEXDUMP_FLAGS;
		case 'b':
			baud = atoi(optarg);
			break;
		case 'f':
			read_from_file = optarg;
			break;
		default: /* '?' */
			fprintf(stderr, "Check source code please\n");
			exit(-1);
			break;
		}
	}

	if (read_from_file) {
		hexmode = 1;
		return serial_dump_record_file(read_from_file);
	}

	if (argc - optind > 0) {
		serialport[0] = argv[optind];
		if (argc - optind > 1) {
			serialport[1] = argv[optind + 1];
			port_num = 2;
		}
	}

	struct sched_param p = {
		.sched_priority = sched_get_priority_max(SCHED_FIFO)
	};
	sched_setscheduler(0, SCHED_FIFO, &p);
	signal(SIGINT, terminate);

	for (int i = 0; i < port_num; i++) {
		serial_fd[i] = serial_connect(serialport[i], baud);
		if (serial_fd[i] < 0)
			return -1;
	}

	struct pollfd pfds[MAX_PORT] = {
		{ .fd = serial_fd[0], .events = POLLIN },
		{ .fd = serial_fd[1], .events = POLLIN },
	};

	while(!done) {
		if(poll(pfds, port_num, -1) > 0) {
			for (int i = 0; i < port_num; i++) {
				if (process_poll_event(&pfds[i], i)) {
					fprintf(stderr, "can't read from %s",
						serialport[i]);
					done = 1;
				}
			}
		}
	}

	for (int i = 0; i < port_num; i++)
		serial_close(serial_fd[i]);

	return 0;
}
#endif

#ifdef PPP_SNIFFER
static struct hdlc_channel {
	struct header 	header;
	unsigned char	striped[4096];
	int 		size;
	int		xor;
} hdlc_channels[MAX_PORT];

/*
 * Wireshark don't expect the HDLC header (7E FF 03) when import hexdump to
 * wireshark, add '-r' param can remove this flag.
 * '-w' will auto select this mode.
 */
static void hdlc_write_data_stream(struct header *header, unsigned char *buf,
				   int remove_hdlc_header)
{
	int skip = 0;

	/* Remove HDLC header 7E FF 03 if need, (not all start with 7E FF 03)
	 * 2019-03-20 17:21:29.402076 -- 0 - 28
	 * 0000 7E FF 03 C0 21 01 01 00  14 02 06 00 00 00 00 05
	 * 2019-03-20 17:21:29.482100 -- 0 - 15
	 * 0000 80 21 01 02 00 0A 03 06  00 00 00 00 6A 10 7E
	 * 2019-03-20 17:21:29.482818 -- 1 - 10
	 * 0000 7E 80 21 01 14 00 04 93  25 7E
	 */
	if (remove_hdlc_header) {
		if (buf[0] == 0x7E) {
			skip++;
			if (buf[1] == 0xFF) {
				skip++;
				if (buf[2] == 0x03) {
					skip++;
				}
			}
		}
	}

	header->len -= skip;
	write_data_stream(header, buf + skip);
}

int main(int argc, char *argv[])
{
	int opt, wireshark_mode = 0, connected = 0 , rmv_hdlc_header = 0;
	FILE *data_stream = stdin;
	unsigned char buf[4096];
	struct header h;

	while ((opt = getopt(argc, argv, HEXDUMP_OPTS "wr")) != -1) {
		switch (opt) {
		CASE_HEXDUMP_FLAGS;
		CASE_OPT_SET_FLAG('w', wireshark_mode);
		CASE_OPT_SET_FLAG('r', rmv_hdlc_header);
		default: /* '?' */
			fprintf(stderr, "Check source code please.\n");
			exit(-1);
			break;
		}
	}

	if (wireshark_mode) {
		hexmode = 1;
		h_with_ns = 1;
		h_with_ascii = 0;
		h_with_len = 0;
		h_with_dir = 1;
		rmv_hdlc_header = 1;
	}

	if (argc - optind > 0) { /* Read data from file */
		data_stream = fopen(argv[optind], "rb");
		if (!data_stream) {
			fprintf(stderr, "can't read from %s\n", argv[optind]);
			exit(-1);
		}
	}

	while (!read_stream(data_stream, &h, buf, sizeof(buf))) {
		struct hdlc_channel *hdlc = &hdlc_channels[h.chn];
		int idx = 0;

		/* Skip garbage such as AT command at startup.
		 * 2019-03-21 09:48:54.131867 - 1 - 11
		 * 0000 0D 0A 43 4F 4E 4E 45 43  54 0D 0A (CONNECT\r\n)
		 * 2019-03-21 09:48:55.139772 - 0 - 8
		 * 0000 7E FF 7D 23 C0 21 7D 21
		 * 2019-03-21 09:48:55.155793 - 0 - 39
		 * 0000 7D 21 7D 20 7D 34 7D 22  7D 26 7D 20 7D 20 7D 20
		 * 0010 7D 20 7D 25 7D 26 7D 2E  79 7D 3A 59 7D 27 7D 22
		 * 0020 7D 28 7D 22 EF 3E 7E
		 * 2019-03-21 09:48:55.155799 - 1 - 34
		 * 0000 7E FF 7D 23 C0 21 7D 21  7D 20 7D 20 7D 38 7D 22
		 * 0010 7D 26 7D 20 7D 20 7D 20  7D 20 7D 23 7D 24 C0 23
		 * 0020 7D 25
		 * 2019-03-21 09:48:55.171713 - 0 - 23
		 * 0000 7E FF 7D 23 C0 21 7D 24  7D 20 7D 20 7D 28 7D 23
		 * 0010 7D 24 C0 23 F9 4B 7E
		 * After the modem responds "CONNECT\r\n", the next packet
		 * are based on HDLC. Stop droping when we got 'CONNECT'
		 * string.
		 * 2019-03-21 09:52:11.159649 - 1 - 18
		 * 0000 7E FF 7D 23 C0 21 7D 26  7D 22 7D 20 7D 24 94 7D
		 * 0010 2D 7E
		 * 2019-03-21 09:52:12.167524 - 1 - 14
		 * 0000 0D 0A 4E 4F 20 43 41 52  52 49 45 52 0D 0A (NO CARRIER)
		 * The serial link are recover to AT after "NO CARRIER\r\n"
		 */
		#define CONNECT_STR		"CONNECT\r\n"
		#define NOCARRIER_STR		"NO CARRIER\r\n"
		if (memmem(buf, h.len, CONNECT_STR, strlen(CONNECT_STR))) {
			connected = 1;
			continue; /* Drop this packet */
		}
		if (memmem(buf, h.len, NOCARRIER_STR, strlen(NOCARRIER_STR))) {
			connected = 0;
			continue; /* Drop this packet */
		}
		/* Drop evering thing if the link are not connected */
		if (!connected)
			continue;
		/*
		 * As we all know, it's hard to know the order of data in
		 * two channel, such as this example:
		 *
		 * 2019-03-20 13:43:45.656530 -- 1 - 74
		 * 0000 7E FF 7D 23 C0 21 7D 21  7D 20 7D 20 7D 38 7D 22
		 * 0010 7D 26 7D 20 7D 20 7D 20  7D 20 7D 23 7D 24 C0 23
		 * 0020 7D 25 7D 26 D9 5C 6B 6F  7D 27 7D 22 7D 28 7D 22
		 * 0030 F7 49 7E 7E FF 7D 23 C0  21 7D 22 7D 21 7D 20 7D
		 * 0040 34 7D 22 7D 26 7D 20 7D  20 7D
		 * 2019-03-20 13:43:45.672606 -- 0 - 23
		 * 0000 7E FF 7D 23 C0 21 7D 24  7D 20 7D 20 7D 28 7D 23
		 * 0010 7D 24 C0 23 F9 4B 7E
		 * 2019-03-20 13:43:45.672735 -- 1 - 22
		 * 0000 20 7D 20 7D 25 7D 26 E5  6F C3 D5 7D 27 7D 22 7D
		 * 0010 28 7D 22 5A 98 7E
		 *
		 * In order to solve this problem, should waiting a full
		 * packet and then hexdump them. As the above example,
		 * 45.656530 is the first part, and 45.672735 is the second.
		 */
		for( ; idx < h.len; idx++) {
			/* There has two type packet, one is start/end with
			 * 7E, and another is stop with 7E, no start flag.
			 */
			if (buf[idx] == 0x7E) {
				if (hdlc->size) { /* meet stop flag */
					hdlc->striped[hdlc->size++] = buf[idx];
					hdlc->header.len = hdlc->size;
					hdlc_write_data_stream(&hdlc->header,
							       hdlc->striped,
							       rmv_hdlc_header);
					hdlc->size = 0;
				} else { /* new packet start/stop with 7E */
					memcpy(&hdlc->header, &h, sizeof(h));
					hdlc->striped[hdlc->size++] = buf[idx];
				}

				/* Both start/end flag should clear xor flag */
				hdlc->xor = 0;
				continue;
			}

			if (hdlc->size == 0) {
				/* new packet without start flag */
				memcpy(&hdlc->header, &h, sizeof(h));
			}

			if (hdlc->xor) {
				hdlc->striped[hdlc->size++] = buf[idx] ^ 0x20;
				hdlc->xor = 0;
			} else if (buf[idx] == 0x7D) {
				hdlc->xor = 1;
			} else {
				hdlc->striped[hdlc->size++] = buf[idx];
			}
		}
	}

	if (data_stream != stdin)
		fclose(data_stream);

	return 0;
}
#endif


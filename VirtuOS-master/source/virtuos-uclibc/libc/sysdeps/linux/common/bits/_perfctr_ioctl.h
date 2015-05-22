#ifndef _PERFCTR_IOCTL_H
#define _PERFCTR_IOCTL_H 1

#define PERFCTR_IOCTL_MAGIC	0xD0
#define PERFCTR_IOCTL_CREAT	_IO(PERFCTR_IOCTL_MAGIC, 6)
#define PERFCTR_IOCTL_OPEN	_IO(PERFCTR_IOCTL_MAGIC, 7)

struct perfctr_cpu_mask {
	unsigned int nrwords;
	unsigned int mask[1];
};

struct perfctr_struct_buf {
	unsigned int rdsize;
	unsigned int wrsize;
	unsigned int buffer[1];
};

#endif

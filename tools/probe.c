/*
 * probe.c — PEGM10 (OPPO Reno5 K 5G) 内核攻击面探针
 *
 * 目标：在内核 4.19.157-perf+ / Android 13 (SDK33) / SPL 2025-06-01 上
 *       确认从 adb shell (uid 2000, u:r:shell:s0) 到底能触达哪些内核驱动接口，
 *       以及这些接口上最基本的原语（open / ioctl / mmap）是否可用。
 *
 * 构建：
 *   clang --target=aarch64-linux-android21 -O2 -static -o probe probe.c
 *
 * 部署：
 *   adb push probe /data/local/tmp/probe
 *   adb shell chmod 755 /data/local/tmp/probe
 *   adb shell /data/local/tmp/probe
 *
 * 说明：本程序只做只读探测与一次 1MB GPU 内存申请/释放，不触发任何越界。
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>

#ifndef __NR_memfd_create
#define __NR_memfd_create 279
#endif

/* ---------------- KGSL (msm-4.19: include/uapi/linux/msm_kgsl.h) ---------------- */
#define KGSL_IOC_TYPE 0x09

struct kgsl_device_getproperty {
	unsigned int type;
	void *value;
	size_t sizebytes;
};

struct kgsl_gpumem_alloc_id {
	unsigned int id;
	unsigned int flags;
	size_t size;
	uint64_t mmapsize;
	uint64_t gpuaddr;
};

struct kgsl_gpumem_get_info {
	uint64_t gpuaddr;
	unsigned int id;
	unsigned int flags;
	size_t size;
	void *mmap_offset;
};

#define IOCTL_KGSL_DEVICE_GETPROPERTY \
	_IOWR(KGSL_IOC_TYPE, 0x02, struct kgsl_device_getproperty)
#define IOCTL_KGSL_GPUMEM_ALLOC_ID \
	_IOWR(KGSL_IOC_TYPE, 0x34, struct kgsl_gpumem_alloc_id)
#define IOCTL_KGSL_GPUMEM_FREE_ID \
	_IOWR(KGSL_IOC_TYPE, 0x35, struct kgsl_gpumem_alloc_id)
#define IOCTL_KGSL_GPUMEM_GET_INFO \
	_IOWR(KGSL_IOC_TYPE, 0x36, struct kgsl_gpumem_get_info)

/* enum kgsl_device_prop_enum */
#define KGSL_PROP_DEVICE_INFO   0x1
#define KGSL_PROP_MMU_ENABLE    0x6
#define KGSL_PROP_INTERRUPT_WAITS 0x7

/* ---------------- binder ---------------- */
struct binder_version { int32_t protocol_version; };
#define BINDER_VERSION _IOWR('b', 9, struct binder_version)

/* ---------------- 工具 ---------------- */
static const char *s(int ok) { return ok ? "OK" : "DENIED"; }

static void probe_open(const char *path)
{
	int fd = open(path, O_RDWR | O_CLOEXEC);
	printf("[open ] %-22s -> %-6s", path, fd >= 0 ? "OK" : "FAIL");
	if (fd < 0)
		printf("  errno=%d (%s)", errno, strerror(errno));
	printf("\n");
	if (fd >= 0)
		close(fd);
}

static void read_small(const char *path)
{
	char buf[128] = {0};
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		printf("[sysfs] %-22s -> FAIL (%s)\n", path, strerror(errno));
		return;
	}
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n > 0) {
		while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\0'))
			buf[--n] = 0;
		printf("[sysfs] %-22s -> %s\n", path, buf);
	} else {
		printf("[sysfs] %-22s -> empty\n", path);
	}
}

/* ---------------- KGSL 探针 ---------------- */
static void probe_kgsl(void)
{
	printf("\n--- KGSL (Adreno) ---\n");
	int fd = open("/dev/kgsl-3d0", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		printf("[kgsl ] open FAIL errno=%d (%s)\n", errno, strerror(errno));
		return;
	}
	printf("[kgsl ] open OK fd=%d\n", fd);

	/* 1. KGSL_PROP_DEVICE_INFO：拿 GPU 版本号，最稳的老 ioctl */
	struct {
		unsigned int gpu_id;
		unsigned int chip_id;
		unsigned int mmu_enabled;
		unsigned int gmem_gpubaseaddr;
		unsigned int gmem_sizebytes;
		unsigned int gmem_hostptr;
		unsigned int gmem_gpuaddr;
	} devinfo = {0};

	struct kgsl_device_getproperty gp = {
		.type = KGSL_PROP_DEVICE_INFO,
		.value = &devinfo,
		.sizebytes = sizeof(devinfo),
	};
	int rc = ioctl(fd, IOCTL_KGSL_DEVICE_GETPROPERTY, &gp);
	printf("[kgsl ] GETPROPERTY(DEVICE_INFO) rc=%d (%s) gpu_id=0x%x chip_id=0x%x mmu=%u gmem=%u\n",
	       rc, rc ? strerror(errno) : "ok",
	       devinfo.gpu_id, devinfo.chip_id, devinfo.mmu_enabled, devinfo.gmem_sizebytes);

	/* 2. KGSL_PROP_MMU_ENABLE */
	unsigned int mmu = 0;
	gp.type = KGSL_PROP_MMU_ENABLE;
	gp.value = &mmu;
	gp.sizebytes = sizeof(mmu);
	rc = ioctl(fd, IOCTL_KGSL_DEVICE_GETPROPERTY, &gp);
	printf("[kgsl ] GETPROPERTY(MMU_ENABLE) rc=%d (%s) mmu=%u\n",
	       rc, rc ? strerror(errno) : "ok", mmu);

	/* 3. GPU 内存申请：证明 kvmalloc/ion 分配原语可达 */
	struct kgsl_gpumem_alloc_id alloc = {0};
	alloc.size = 1024 * 1024;
	alloc.flags = 0x10000000; /* KGSL_MEMFLAGS_GPUREADONLY 之外，用 0 亦可 */
	alloc.flags = 0;
	rc = ioctl(fd, IOCTL_KGSL_GPUMEM_ALLOC_ID, &alloc);
	printf("[kgsl ] GPUMEM_ALLOC_ID 1MB rc=%d (%s) id=%u gpuaddr=0x%llx mmapsize=%llu\n",
	       rc, rc ? strerror(errno) : "ok",
	       alloc.id, (unsigned long long)alloc.gpuaddr,
	       (unsigned long long)alloc.mmapsize);

	if (rc == 0) {
		struct kgsl_gpumem_get_info gi = {0};
		gi.id = alloc.id;
		rc = ioctl(fd, IOCTL_KGSL_GPUMEM_GET_INFO, &gi);
		printf("[kgsl ] GPUMEM_GET_INFO   rc=%d (%s) size=%zu offset=%p\n",
		       rc, rc ? strerror(errno) : "ok", gi.size, gi.mmap_offset);

		/* mmap 该对象，验证 user 侧可读写映射 */
		if (rc == 0 && gi.mmap_offset) {
			void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
				       MAP_SHARED, fd, (off_t)(uintptr_t)gi.mmap_offset);
			if (m != MAP_FAILED) {
				printf("[kgsl ] mmap OK %p\n", m);
				munmap(m, 4096);
			} else {
				printf("[kgsl ] mmap FAIL (%s)\n", strerror(errno));
			}
		}

		struct kgsl_gpumem_alloc_id fr = {0};
		fr.id = alloc.id;
		fr.size = alloc.size;
		rc = ioctl(fd, IOCTL_KGSL_GPUMEM_FREE_ID, &fr);
		printf("[kgsl ] GPUMEM_FREE_ID   rc=%d (%s)\n", rc, rc ? strerror(errno) : "ok");
	}

	close(fd);
}

/* ---------------- binder 探针 ---------------- */
static void probe_binder(const char *path)
{
	printf("\n--- binder: %s ---\n", path);
	int fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		printf("[bind ] open FAIL errno=%d (%s)\n", errno, strerror(errno));
		return;
	}
	struct binder_version v = {0};
	int rc = ioctl(fd, BINDER_VERSION, &v);
	printf("[bind ] BINDER_VERSION rc=%d (%s) protocol=%d\n",
	       rc, rc ? strerror(errno) : "ok", v.protocol_version);
	close(fd);
}

/* ---------------- 其它可达节点 ---------------- */
static void probe_misc(void)
{
	printf("\n--- ion / ashmem / memfd ---\n");

	int fd = open("/dev/ion", O_RDONLY | O_CLOEXEC);
	printf("[ion  ] open(%s) -> %s\n", "O_RDONLY",
	       fd >= 0 ? "OK" : (char *)strerror(errno));
	if (fd >= 0) close(fd);

	fd = open("/dev/ashmem", O_RDWR | O_CLOEXEC);
	printf("[ashm ] /dev/ashmem -> %s\n", fd >= 0 ? "OK" : (char *)strerror(errno));
	if (fd >= 0) close(fd);

	long mfd = syscall(__NR_memfd_create, "probe", 0);
	printf("[memfd] memfd_create -> %s (fd=%ld)\n",
	       mfd >= 0 ? "OK" : strerror(errno), mfd);
	if (mfd >= 0) {
		if (ftruncate((int)mfd, 4096) == 0) {
			void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, (int)mfd, 0);
			printf("[memfd] mmap -> %s %p\n", p != MAP_FAILED ? "OK" : strerror(errno), p);
			if (p != MAP_FAILED) munmap(p, 4096);
		}
		close((int)mfd);
	}
}

/* ---------------- 报告头 ---------------- */
static void header(void)
{
	struct utsname u;
	uname(&u);
	printf("==== PEGM10 attack-surface probe ====\n");
	printf("[kern ] %s %s\n", u.sysname, u.release);
	printf("[uid  ] %d euid=%d gid=%d\n", getuid(), geteuid(), getgid());

	char ctx[256] = {0};
	int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		ssize_t n = read(fd, ctx, sizeof(ctx) - 1);
		close(fd);
		if (n > 0) {
			while (n > 0 && (ctx[n-1] == '\n' || ctx[n-1] == '\0')) ctx[--n] = 0;
			printf("[selin] %s\n", ctx);
		}
	}

	read_small("/proc/sys/kernel/kptr_restrict");
	read_small("/proc/sys/kernel/perf_event_paranoid");
	read_small("/sys/class/kgsl/kgsl-3d0/gpu_model");
	read_small("/sys/class/kgsl/kgsl-3d0/gpu_available_frequencies");
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	header();

	printf("\n--- 设备节点 open 测试 ---\n");
	probe_open("/dev/kgsl-3d0");
	probe_open("/dev/binder");
	probe_open("/dev/hwbinder");
	probe_open("/dev/vndbinder");
	probe_open("/dev/ion");
	probe_open("/dev/ashmem");
	probe_open("/dev/diag");
	probe_open("/dev/qseecom");
	probe_open("/dev/msm_npu");
	probe_open("/dev/msm_hdcp");

	probe_kgsl();
	probe_binder("/dev/binder");
	probe_binder("/dev/hwbinder");
	probe_misc();

	printf("\n==== probe done ====\n");
	return 0;
}

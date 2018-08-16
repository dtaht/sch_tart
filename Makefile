obj-m := sch_tart.o
KERNEL_VERSION := $(shell uname -r)
IDIR := /lib/modules/$(KERNEL_VERSION)/kernel/net/sched/
KDIR := /lib/modules/$(KERNEL_VERSION)/build
PWD := $(shell pwd)
VERSION := $(shell git rev-parse HEAD 2>/dev/null)
default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules $(if $(VERSION),LDFLAGS_MODULE="--build-id=0x$(VERSION)" CFLAGS_MODULE="-DCAKE_VERSION=\\\"$(VERSION)\\\"")

install:
	install -v -m 644 sch_tart.ko $(IDIR)
	depmod
	modprobe sch_tart

clean:
	rm -rf Module.markers modules.order Module.symvers sch_tart.ko sch_tart.mod.c sch_tart.mod.o sch_tart.o

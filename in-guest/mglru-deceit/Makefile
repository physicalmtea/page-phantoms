obj-m += mglru-deceit.o
KDIR ?= /lib/modules/$(shell uname -r)/build
KBUILD_CFLAGS += -Wno-frame-larger-than

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

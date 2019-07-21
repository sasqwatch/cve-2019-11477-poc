PWD := $(shell pwd)

obj-m += interceptor.o
#ccflags-y := -I$(PWD)/../../include
ccflags-y := -DDEBUG -DFINFO
interceptor-objs	:= catcher.o

KDIR := /lib/modules/$(shell uname -r)/build
#KDIR := $(HOME)/linux

all: 
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

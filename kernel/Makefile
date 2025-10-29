obj-m += mservtime.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) ccflags-y="-DCONFIG_NETFILTER -DCONFIG_NETFILTER_INGRESS" modules 
bear:
	bear -- make -C /lib/modules/$(shell uname -r)/build M=$(PWD) ccflags-y="-DCONFIG_NETFILTER -DCONFIG_NETFILTER_INGRESS" modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


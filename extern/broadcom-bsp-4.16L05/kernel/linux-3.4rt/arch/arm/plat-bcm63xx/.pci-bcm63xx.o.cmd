cmd_arch/arm/plat-bcm63xx/pci-bcm63xx.o := /opt/toolchains/crosstools-arm-gcc-4.6-linux-3.4-uclibc-0.9.32-binutils-2.21-NPTL/usr/bin/arm-unknown-linux-uclibcgnueabi-gcc -Wp,-MD,arch/arm/plat-bcm63xx/.pci-bcm63xx.o.d  -nostdinc -isystem /opt/toolchains/crosstools-arm-gcc-4.6-linux-3.4-uclibc-0.9.32-binutils-2.21-NPTL/usr/lib/gcc/arm-unknown-linux-uclibcgnueabi/4.6.2/include -I/home/users/popeye_shen/ac88u-gpl/bcm963xx/kernel/linux-3.4rt/arch/arm/include -Iarch/arm/include/generated -Iinclude  -include /home/users/popeye_shen/ac88u-gpl/bcm963xx/kernel/linux-3.4rt/include/linux/kconfig.h -I/extern/broadcom-bsp-4.16L05/shared/opensource/include/bcm963xx -D__KERNEL__ -mlittle-endian -Iarch/arm/mach-bcm963xx/include -Iarch/arm/plat-bcm63xx/include -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration -Wno-format-security -fno-delete-null-pointer-checks -O2 -marm -fno-dwarf2-cfi-asm -mabi=aapcs-linux -mno-thumb-interwork -funwind-tables -D__LINUX_ARM_ARCH__=7 -march=armv7-a -msoft-float -Uarm -Wframe-larger-than=2048 -fno-stack-protector -Wno-unused-but-set-variable -fomit-frame-pointer -Wdeclaration-after-statement -Wno-pointer-sign -fno-strict-overflow -fconserve-stack -DARCADYAN -g -Werror -Wfatal-errors -I/home/users/popeye_shen/ac88u-gpl/bcm963xx/shared/opensource/boardparms/bcm963xx -I/include -I/home/users/popeye_shen/ac88u-gpl/bcm963xx/bcmdrivers/opensource/include/bcm963xx -I/home/users/popeye_shen/ac88u-gpl/bcm963xx/shared/opensource/include/bcm963xx -I/home/users/popeye_shen/ac88u-gpl/bcm963xx/shared/opensource/include/pmc    -D"KBUILD_STR(s)=\#s" -D"KBUILD_BASENAME=KBUILD_STR(pci_bcm63xx)"  -D"KBUILD_MODNAME=KBUILD_STR(pci_bcm63xx)" -c -o arch/arm/plat-bcm63xx/pci-bcm63xx.o arch/arm/plat-bcm63xx/pci-bcm63xx.c

source_arch/arm/plat-bcm63xx/pci-bcm63xx.o := arch/arm/plat-bcm63xx/pci-bcm63xx.c

deps_arch/arm/plat-bcm63xx/pci-bcm63xx.o := \

arch/arm/plat-bcm63xx/pci-bcm63xx.o: $(deps_arch/arm/plat-bcm63xx/pci-bcm63xx.o)

$(deps_arch/arm/plat-bcm63xx/pci-bcm63xx.o):
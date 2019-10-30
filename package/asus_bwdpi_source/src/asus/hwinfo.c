/*
	hwinfo.c for program control v2.11
	v2.8  : 2017/01/19
	v2.9  : 2017/02/13
	v2.10 : 2017/02/22
	v2.11 : 2017/03/29
	v2.12 : 2017/04/13
	v2.13 : 2017/04/13
	v2.14 : 2017/04/14
*/


// header not to combine with bwdpi.h for prebuilt testing
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <asus_nvram.h>
//#include <bcmnvram.h>
//#include <shutils.h>
//#include <shared.h>

enum {
	MODEL_GENERIC = -1,
	MODEL_UNKNOWN = 0,
	MODEL_DSLAC87VG,
	MODEL_DSLAC88U,
	MODEL_DSLAC3100,
	MODEL_DSLAC88UB,
	MODEL_DSLAC68VG,
};

struct model_s {
	char *pid;
	int model;
};

static const struct model_s model_list[] = {
	{ "DSL-AC87VG",		MODEL_DSLAC87VG	},
	{ "DSL-AC88U",		MODEL_DSLAC88U	},
	{ "DSL-AC3100",		MODEL_DSLAC3100	},
	{ "DSL-AC88U-B",	MODEL_DSLAC88UB	},
	{ "DSL-AC68VG",		MODEL_DSLAC68VG	},
	{ NULL, 0 },
};

/* returns MODEL ID
 * result is cached for safe multiple use */
int get_model(void)
{
	static int model = MODEL_UNKNOWN;
	char *pid;
	const struct model_s *p;

	if (model != MODEL_UNKNOWN)
		return model;

	pid = nvram_safe_get("productid");
	for (p = &model_list[0]; p->pid; ++p) {
		if (!strcmp(pid, p->pid)) {
			model = p->model;
			break;
		}
	}

	return model;
}

static char *hwinfo_btn_rst_gpio()
{
	switch (get_model()) {
		case MODEL_DSLAC87VG:
			return "32\n";
		case MODEL_DSLAC88U:
			return "32\n";
		case MODEL_DSLAC3100:
			return "32\n";
		case MODEL_DSLAC88UB:
			return "32\n";
		case MODEL_DSLAC68VG:
			return "32\n";
		default:
			return "32\n";
	}
}

static char *hwinfo_btn_wps_gpio()
{
	switch (get_model()) {
		case MODEL_DSLAC87VG:
			return "33\n";
		case MODEL_DSLAC88U:
			return "33\n";
		case MODEL_DSLAC3100:
			return "33\n";
		case MODEL_DSLAC88UB:
			return "33\n";
		case MODEL_DSLAC68VG:
			return "33\n";
		default:
			return "33\n";
	}
}

static char *hwinfo_btn_led_gpio()
{
	switch (get_model()) {
		case MODEL_DSLAC87VG:
			return "33\n";
		case MODEL_DSLAC88U:
			return "36\n";
		case MODEL_DSLAC3100:
			return "36\n";
		case MODEL_DSLAC88UB:
			return "36\n";
		case MODEL_DSLAC68VG:
			return "34\n";
		default:
			return "36\n";
	}
}

static char *hwinfo_btn_wltog_gpio()
{
	switch (get_model()) {
		case MODEL_DSLAC87VG:
			return "35\n";
		case MODEL_DSLAC88U:
			return "12\n";
		case MODEL_DSLAC3100:
			return "12\n";
		case MODEL_DSLAC88UB:
			return "12\n";
		case MODEL_DSLAC68VG:
			return "33\n";
		default:
			return "12\n";
	}
}

/*
	note : venidXg must use "16 digits (HEX)" for TrendMicro, it's their logic for judgement
*/
static char *hwinfo_venid2g()
{
	switch (get_model()) {
		case MODEL_DSLAC87VG:
			return "0x14E4\n";
		case MODEL_DSLAC88U:
			return "0x14E4\n";
		case MODEL_DSLAC3100:
			return "0x14E4\n";
		case MODEL_DSLAC88UB:
			return "0x14E4\n";
		case MODEL_DSLAC68VG:
			return "0x14E4\n";
		default:
			return "0x14E4\n";
	}
}

static char *hwinfo_venid5g()
{
	switch (get_model()) {
		case MODEL_DSLAC87VG:
			return "bbic4_rev_a2\n";
		case MODEL_DSLAC88U:
			return "0x14E4\n";
		case MODEL_DSLAC3100:
			return "0x14E4\n";
		case MODEL_DSLAC88UB:
			return "0x14E4\n";
		case MODEL_DSLAC68VG:
			return "0x14E4\n";
		default:
			return "0x14E4\n";
	}
}

static char *hwinfo_clm_data_ver()
{
	switch (get_model()) {
		case MODEL_DSLAC87VG:
			return "DSL-AC87VG\n";
		case MODEL_DSLAC88U:
			return "DSL-AC88U\n";
		case MODEL_DSLAC3100:
			return "DSL-AC3100\n";
		case MODEL_DSLAC88UB:
			return "DSL-AC88U-B\n";
		case MODEL_DSLAC68VG:
			return "DSL-AC68VG\n";
		default:
			return "\n";
	}
}

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "productid"))
	{
		system("nvram get productid");
	}
	else if (argc == 2 && !strcmp(argv[1], "btn_rst_gpio"))
	{
		printf("%s", hwinfo_btn_rst_gpio());
	}
	else if (argc == 2 && !strcmp(argv[1], "btn_wps_gpio"))
	{
		printf("%s", hwinfo_btn_wps_gpio());
	}
	else if (argc == 2 && !strcmp(argv[1], "btn_led_gpio"))
	{
		printf("%s", hwinfo_btn_led_gpio());
	}
	else if (argc == 2 && !strcmp(argv[1], "btn_wltog_gpio"))
	{
		printf("%s", hwinfo_btn_wltog_gpio());
	}
	else if (argc == 2 && !strcmp(argv[1], "venid2g"))
	{
		printf("%s", hwinfo_venid2g());
	}
	else if (argc == 2 && !strcmp(argv[1], "venid5g"))
	{
		printf("%s", hwinfo_venid5g());
	}
	else if (argc == 2 && !strcmp(argv[1], "clm_data_ver"))
	{
		printf("%s", hwinfo_clm_data_ver());
	}
	else
		return 0;

	return 1;
}

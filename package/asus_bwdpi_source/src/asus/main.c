/*
	for bwdpi_cmd
*/
#include "bwdpi.h"

int main(int argc, char **argv)
{
	if (argc == 1) return 0;

	if (!strcmp(argv[1], "qosd") && argc == 2)
	{
		qosd_main(argv[2]);
	}
	else if (!strcmp(argv[1], "sig_ver") && argc == 2)
	{
		save_version_of_bwdpi();
	}
	else if (!strcmp(argv[1], "qos_conf") && argc == 2)
	{
		setup_qos_conf();
	}
	else
	{
		printf("no such command\n");
	}

	return 1;
}

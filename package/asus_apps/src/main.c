#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "asus_nvram.h"
#include "arcgpl.h"

int main(int argc, char *argv[])
{
	int i;
	char *cmd;
	char *args[10];
	FILE *fp = NULL;
	int pid;
	char buffer[512];

	if (argc > 1 && argv[1] != NULL)
	{
		cmd = argv[1];
		if (argc > 2 && argv[2] != NULL)
		{
			if (strcmp(cmd, "get") == 0)
			{
				printf("%s\n", nvram_get(argv[2]));
				return 0;
			}
			else if (strcmp(cmd, "set") == 0)
				return nvarm_set_cmd(argv[2]);
		}
		else if (strcmp(cmd, "commit") == 0)
			return nvram_commit();
	}

	for (i = 1; i<argc && i<10-1; i++)
		args[i] = argv[i];
	args[0] = "/usr/sbin/nvram";
	args[i] = NULL;

	fp = exec_open(&pid, args);
	if (fp != NULL)
	{
		while(fgets(buffer, sizeof(buffer), fp) != NULL)
			printf("%s", buffer);
		exec_close(pid, fp);
	}
	
	return 0;
}

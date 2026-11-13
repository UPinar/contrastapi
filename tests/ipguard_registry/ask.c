#include <stdio.h>
#include <string.h>

#include "ipguard.h"

int main(void)
{
  char line[128];
  while (fgets(line, sizeof(line), stdin) != NULL)
  {
    line[strcspn(line, "\n")] = '\0';
    printf("%s %d\n", line, ipguard_isGloballyReachableIp(line) ? 1 : 0);
  }
  return 0;
}

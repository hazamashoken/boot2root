int func4(int param_1)
{
  int iVar1;
  int iVar2;
  
  if (param_1 < 2) {
    iVar2 = 1;
  }
  else {
    iVar1 = func4(param_1 + -1);
    iVar2 = func4(param_1 + -2);
    iVar2 = iVar2 + iVar1;
  }
  return iVar2;
}

#include <stdio.h>

int main(void) {
    int num = 2;
    while (1) {
        if (func4(num) == 55){
            printf(">>> %d\n", num);
            return 0;
        }
        num++;
    }
    return 0;
}
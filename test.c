#include "stdio.h"

int starter02(char* param_1, char* param_2) {
  char* c1 = param_1;
  char* c2 = param_2;
  int result;

  while (1) {
    if (*c1 != *c2) {
      if (*c1 < *c2)
        result = -1;
      else
        result = 1;
      return result;
    }
    if (*c1 == '\0') break;
    c1++;
    c2++;
  }
  return 0;
}

int test(char* param_1, char* param_2) {
  char* c1 = param_1;
  char* c2 = param_2;
  while (1) {
    if (*c1 < *c2) return -1;
    else if (*c1 > *c2) return 1;
    else if (*c1 == '\0') return 0;
    c1++; c2++;
  }
}

int main() {
  char* p1 = "tristan";
  char* p2 = "tristan";
  printf("result: %d\n", starter02(p1, p2));
  printf("result: %d\n", test(p1, p2));
}


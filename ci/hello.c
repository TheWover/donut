#include <stdio.h>

int main(void) {
  FILE *marker = fopen("donut_payload_ok.txt", "wb");
  if (marker == NULL) {
    return 2;
  }

  fputs("donut payload executed\n", marker);
  fclose(marker);
  return 0;
}

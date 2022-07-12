#include <stdlib.h>
#include <stdio.h>

#include "../src/client.h"

int main(int argc, char *argv[]) {
    Client *c = new Client();
    //c->ReadFromStorage();
    fprintf(stderr, "det2f: starting initialize\n");
    c->Initialize();
    fprintf(stderr, "det2f: finished initialize\n");
    c->WriteToStorage();
}

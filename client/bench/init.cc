#include <stdlib.h>
#include <stdio.h>

#include "../src/client.h"

int main(int argc, char *argv[]) {
    Client *c = new Client("");
    //c->ReadFromStorage();
    c->Initialize();
    c->WriteToStorage();
}

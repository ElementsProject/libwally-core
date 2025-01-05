/* Tests that including the entire library as a single source file works */
#include "../amalgamation/combined.c"

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;

    wally_init(0);
    return wally_cleanup(0);
}

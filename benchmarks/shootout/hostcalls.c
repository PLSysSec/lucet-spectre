#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#include <lucet.h>

uint32_t change_mpk_domain(uint32_t domain);
uint32_t get_mpk_domain();

void
sg_log(struct lucet_vmctx *ctx, guest_ptr_t msg_ptr)
{
    #ifdef USE_MPK
        uint32_t original = get_mpk_domain();
        const uint32_t all_memory = 0; // 0b0000
        change_mpk_domain(all_memory);
    #endif

    char *heap = lucet_vmctx_get_heap(ctx);

    const char *msg = (const char *) &heap[msg_ptr];
    printf("* DEBUG: [%s]\n", msg);

    #ifdef USE_MPK
        change_mpk_domain(original);
    #endif
}

void
sg_black_box(void *x)
{
    (void) x;
}

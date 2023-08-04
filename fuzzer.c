#include "giftcard.h"

#include <stdint.h>

extern void print_gift_card_info(struct this_gift_card *thisone);
extern struct this_gift_card *gift_card_reader_buf(const uint8_t * buf, long bufsize);

void free_gift_card(struct this_gift_card * gc) {
    struct gift_card_data *gcd_ptr = NULL;
    struct gift_card_record_data *gcrd_ptr = NULL;
    struct gift_card_amount_change *gcac_ptr = NULL;
    struct gift_card_program *gcp_ptr = NULL;
    if (gc != NULL) {
        gcd_ptr = gc->gift_card_data;
        if (gcd_ptr != NULL) {
            // puts("free gcd_ptr innards");
            free(gcd_ptr->merchant_id);
            free(gcd_ptr->customer_id);
            if (gcd_ptr->gift_card_record_data != NULL) {
                for (int i = 0; i < gcd_ptr->number_of_gift_card_records; i++) {
                    // printf("free gcd_ptr rec: %d\n", i);
                    gcrd_ptr = gcd_ptr->gift_card_record_data[i];
                    if (gcrd_ptr!=NULL && gcrd_ptr->actual_record!=NULL) {
                        switch (gcrd_ptr->type_of_record)
                        {
                        case 1:
                            // puts("free rec type 1");
                            gcac_ptr = gcrd_ptr->actual_record;
                            free(gcac_ptr->actual_signature);
                            break;
                        case 3:
                            // puts("free rec type 3");
                            gcp_ptr = gcrd_ptr->actual_record;
                            free(gcp_ptr->message);
                            free(gcp_ptr->program);
                        }
                        free(gcrd_ptr->actual_record);
                    } else if (gcrd_ptr == NULL) break;
                    free(gcrd_ptr);
            }}
            free(gcd_ptr->gift_card_record_data);
        }
        free(gcd_ptr);
        free(gc);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // code that calls your API here
    struct this_gift_card *thisone = gift_card_reader_buf(Data, Size);
    if (thisone != NULL) {
        print_gift_card_info(thisone);
        free_gift_card(thisone);
    }
    return 0;
}
/*
 * Gift Card Reading Application
 * Original Author: Shoddycorp's Cut-Rate Contracting
 * Comments added by: Justin Cappos (JAC) and Brendan Dolan-Gavitt (BDG)
 * Maintainer:
 * Date: 8 July 2020
 */


#include "giftcard.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#define assert(a) if (!(a)) goto error;

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
// function in fuzzer.c to prevent memory leaks during fuzzing
extern void free_gift_card(struct this_gift_card * gc);
#endif

// check location of null character in buf, of length len bytes
int str_null_loc(const char * buf, int len) {
    for(int i = 0; i < len; ++i) {
        if(buf[i] == '\0') return i;
    }
    return -1;
}

// .,~==== interpreter for THX-1138 assembly ====~,.
//
// This is an emulated version of a microcontroller with
// 16 registers, one flag (the zero flag), and display
// functionality. Programs can operate on the message
// buffer and use opcode 0x07 to update the display, so
// that animated greetings can be created.
void animate(char *msg, unsigned char *program) {
    unsigned char regs[16] = {0};
    char *mptr = msg;
    unsigned char *pc = program;
    int i = 0;
    int zf = 0;
    while (pc < program+254) {
        signed char op, arg1, arg2;
        op = *pc;
        arg1 = *(pc+1);
        arg2 = *(pc+2);
        pc+=3;
        switch (op) {
            case 0x00:
                break;
            case 0x01:
                assert(arg1>=0 && arg1<=15);
                regs[arg1] = *mptr;
                break;
            case 0x02:
                assert(arg1>=0 && arg1<=15);
                *mptr = regs[arg1];
                assert(mptr >= msg && mptr < msg+32);
                break;
            case 0x03:
                mptr += (char)arg1;
                assert(mptr >= msg && mptr < msg+32);
                break;
            case 0x04:
                assert(arg2>=0 && arg2<=15);
                regs[arg2] = arg1;
                break;
            case 0x05:
                assert(arg1>=0 && arg1<=15 && arg2>=0 && arg2<=15);
                regs[arg1] ^= regs[arg2];
                zf = !regs[arg1];
                break;
            case 0x06:
                assert(arg1>=0 && arg1<=15 && arg2>=0 && arg2<=15);
                regs[arg1] += regs[arg2];
                zf = !regs[arg1];
                break;
            case 0x07:
                assert(str_null_loc(msg, 32) > 0);
                puts(msg);
                break;
            case 0x08:
                goto done;
            case 0x09:
                assert(arg1>=0);
                pc += (char)arg1;
                break;
            case 0x10:
                assert(arg1>=0);
                if (zf) pc += (char)arg1;
                break;
            default:
                goto error;
        }
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        // Slow down animation to make it more visible (disabled if fuzzing)
        usleep(5000);
#endif
    }
done:
    return;
error:
fprintf(stderr, "Invalid gift card program.\n");
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    return;
#else
    exit(1);
#endif
}

int get_gift_card_value(struct this_gift_card *thisone) {
    struct gift_card_data *gcd_ptr;
    struct gift_card_record_data *gcrd_ptr;
    struct gift_card_amount_change *gcac_ptr;
    int ret_count = 0;

    gcd_ptr = thisone->gift_card_data;
    for(int i=0;i<gcd_ptr->number_of_gift_card_records; i++) {
          gcrd_ptr = (struct gift_card_record_data *) gcd_ptr->gift_card_record_data[i];
        if (gcrd_ptr->type_of_record == 1) {
            gcac_ptr = gcrd_ptr->actual_record;
            ret_count += gcac_ptr->amount_added;
        }	
    }
    return ret_count;
}

void print_gift_card_info(struct this_gift_card *thisone) {
    struct gift_card_data *gcd_ptr;
    struct gift_card_record_data *gcrd_ptr;
    struct gift_card_amount_change *gcac_ptr;
    struct gift_card_program *gcp_ptr;

    gcd_ptr = thisone->gift_card_data;
    printf("   Merchant ID: %32.32s\n",gcd_ptr->merchant_id);
    printf("   Customer ID: %32.32s\n",gcd_ptr->customer_id);
    printf("   Num records: %d\n",gcd_ptr->number_of_gift_card_records);
    for(int i=0;i<gcd_ptr->number_of_gift_card_records; i++) {
          gcrd_ptr = (struct gift_card_record_data *) gcd_ptr->gift_card_record_data[i];
        if (gcrd_ptr->type_of_record == 1) {
            printf("      record_type: amount_change\n");
            gcac_ptr = gcrd_ptr->actual_record;
            printf("      amount_added: %d\n",gcac_ptr->amount_added);
            if (gcac_ptr->amount_added>0) {
                printf("      signature: %32.32s\n",gcac_ptr->actual_signature);
            }
        }	
        else if (gcrd_ptr->type_of_record == 2) {
            printf("      record_type: message\n");
            printf("      message: %s\n",(char *)gcrd_ptr->actual_record);
        }
        else if (gcrd_ptr->type_of_record == 3) {
            gcp_ptr = gcrd_ptr->actual_record;
            printf("      record_type: animated message\n");
            // BDG: Hmm... is message guaranteed to be null-terminated?
            printf("      message: %s\n", gcp_ptr->message);
            printf("  [running embedded program]  \n");
            animate(gcp_ptr->message, gcp_ptr->program);
        }
    }
    printf("  Total value: %d\n\n",get_gift_card_value(thisone));
}

// Added to support web functionalities
void gift_card_json(struct this_gift_card *thisone) {
    struct gift_card_data *gcd_ptr;
    struct gift_card_record_data *gcrd_ptr;
    struct gift_card_amount_change *gcac_ptr;
    gcd_ptr = thisone->gift_card_data;
    printf("{\n");
    printf("  \"merchant_id\": \"%32.32s\",\n", gcd_ptr->merchant_id);
    printf("  \"customer_id\": \"%32.32s\",\n", gcd_ptr->customer_id);
    printf("  \"total_value\": %d,\n", get_gift_card_value(thisone));
    printf("  \"records\": [\n");
    for(int i=0;i<gcd_ptr->number_of_gift_card_records; i++) {
        gcrd_ptr = (struct gift_card_record_data *) gcd_ptr->gift_card_record_data[i];
        printf("    {\n");
        if (gcrd_ptr->type_of_record == 1) {
            printf("      \"record_type\": \"amount_change\",\n");
            gcac_ptr = gcrd_ptr->actual_record;
            printf("      \"amount_added\": %d,\n",gcac_ptr->amount_added);
            if (gcac_ptr->amount_added>0) {
                printf("      \"signature\": \"%32.32s\"\n",gcac_ptr->actual_signature);
            }
        }
        else if (gcrd_ptr->type_of_record == 2) {
            printf("      \"record_type\": \"message\",\n");
            printf("      \"message\": \"%s\"\n",(char *)gcrd_ptr->actual_record);
        }
        else if (gcrd_ptr->type_of_record == 3) {
            struct gift_card_program *gcp = gcrd_ptr->actual_record;
            printf("      \"record_type\": \"animated message\",\n");
            printf("      \"message\": \"%s\",\n",gcp->message);
            // programs are binary so we will hex for the json
            char *hexchars = "01234567890abcdef";
            char program_hex[512+1];
            program_hex[512] = '\0';
            int i;
            for(i = 0; i < 256; i++) {
                program_hex[i*2] = hexchars[((gcp->program[i] & 0xf0) >> 4)];
                program_hex[i*2+1] = hexchars[(gcp->program[i] & 0x0f)];
            }
            printf("      \"program\": \"%s\"\n",program_hex);
        }
        if (i < gcd_ptr->number_of_gift_card_records-1)
            printf("    },\n");
        else
            printf("    }\n");
    }
    printf("  ]\n");
    printf("}\n");
}

struct this_gift_card *__gift_card_reader(const uint8_t * buf, long bufsize) {
    const uint8_t *ptr = buf;
    const uint8_t *bufend = buf + bufsize;
    struct this_gift_card *ret_val = calloc(sizeof(struct this_gift_card), 1);
    struct gift_card_data *gcd_ptr = NULL;
    struct gift_card_record_data *gcrd_ptr = NULL;
    struct gift_card_amount_change *gcac_ptr = NULL;
    struct gift_card_program *gcp_ptr = NULL;

    // begin reading gift card
    assert(ptr+4 < bufend);
    ret_val->num_bytes = *(int*)ptr;
    ptr += 4;
    assert(ret_val->num_bytes == bufsize);

    //populating giftcarddata
    assert(ptr+68 < bufend);
    gcd_ptr = ret_val->gift_card_data = calloc(sizeof(struct gift_card_data), 1);
    gcd_ptr->merchant_id = calloc(32, 1);
    memcpy(gcd_ptr->merchant_id, ptr, 32);
    assert(str_null_loc(gcd_ptr->merchant_id, 32) > 0)
    ptr += 32;
    gcd_ptr->customer_id = calloc(32, 1);
    memcpy(gcd_ptr->customer_id, ptr, 32);
    assert(str_null_loc(gcd_ptr->customer_id, 32) > 0)
    ptr += 32;
    gcd_ptr->number_of_gift_card_records = *((int *)ptr);
    ptr += 4;
    // printf("Populated giftcarddata: %d records\n", gcd_ptr->number_of_gift_card_records);

    assert(gcd_ptr->number_of_gift_card_records > 0 && gcd_ptr->number_of_gift_card_records < 100);
    gcd_ptr->gift_card_record_data = (void **)calloc(gcd_ptr->number_of_gift_card_records*sizeof(void*), 1);
    
    // Now ptr points at the gift card record data
    for (int i=0; i < gcd_ptr->number_of_gift_card_records; i++){
        // printf("giftcardrecord: %d\n",i);
        assert(ptr+8 < bufend);
        gcrd_ptr = gcd_ptr->gift_card_record_data[i] = calloc(sizeof(struct gift_card_record_data), 1);

        gcrd_ptr->record_size_in_bytes = *((int *)ptr);
        // printf("rec at %lx, %d bytes\n", ptr - buf, gcrd_ptr->record_size_in_bytes);
        ptr += 4;
        // printf("record_data: %d\n",gcrd_ptr->record_size_in_bytes);
        gcrd_ptr->type_of_record = *((int *)ptr);
        ptr += 4;
        // printf("type of rec: %d\n", gcrd_ptr->type_of_record);
        assert(gcrd_ptr->record_size_in_bytes > 8);

        // amount change
        if (gcrd_ptr->type_of_record == 1) {
            assert(ptr+4 <= bufend);
            gcac_ptr = gcrd_ptr->actual_record = calloc(sizeof(struct gift_card_amount_change), 1);
            gcac_ptr->amount_added = *((int*) ptr);
            ptr += 4;
            if (gcac_ptr->amount_added <= 0 && gcrd_ptr->record_size_in_bytes == 12) {
                continue;
            } else if (gcac_ptr->amount_added > 0 && gcrd_ptr->record_size_in_bytes == 44) {
                assert(ptr+32 <= bufend);
                gcac_ptr->actual_signature = calloc(32, 1);
                memcpy(gcac_ptr->actual_signature, ptr, 32);
                assert(str_null_loc(gcac_ptr->actual_signature, 32) > 0);
                ptr += 32;
                continue;
            } else {
                goto error;
            }
        }
        // message
        else if (gcrd_ptr->type_of_record == 2) {
            assert(ptr+gcrd_ptr->record_size_in_bytes-8 <= bufend);
            int str_len = str_null_loc((char*)ptr, gcrd_ptr->record_size_in_bytes-8);
            assert(str_len > 0);
            assert(gcrd_ptr->record_size_in_bytes == str_len + 9)
            gcrd_ptr->actual_record = calloc(str_len + 1, 1);
            memcpy(gcrd_ptr->actual_record, ptr, str_len + 1);
            ptr += str_len + 1;
        }
        // animation
        else if (gcrd_ptr->type_of_record == 3) {
            assert(ptr+288 <= bufend);
            assert(gcrd_ptr->record_size_in_bytes == 296);
            gcp_ptr = gcrd_ptr->actual_record = calloc(sizeof(struct gift_card_program), 1);
            gcp_ptr->message = calloc(32, 1);
            gcp_ptr->program = calloc(256, 1);
            memcpy(gcp_ptr->message, ptr, 32);
            assert(str_null_loc(gcp_ptr->message, 32) > 0);
            ptr+=32;
            memcpy(gcp_ptr->program, ptr, 256);
            ptr+=256;
        }
        else {
            goto error;
        }
    }
    if (ptr != bufend) {
        goto error;
    }
    return ret_val;

error:
    fprintf(stderr, "Invalid gift card.\n");
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    free_gift_card(ret_val);
    return NULL;
#else
    exit(1);
#endif
}

struct this_gift_card *gift_card_reader(FILE *fp) {
    struct this_gift_card *ret_val;
    uint8_t *buf;
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    rewind(fp);
    buf = calloc(fsize, 1);
    fread(buf, 1, fsize, fp);
    ret_val = __gift_card_reader(buf, fsize);
    free(buf);
    return ret_val;
}

struct this_gift_card *thisone;

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <1|2> file.gft\n", argv[0]);
        fprintf(stderr, "  - Use 1 for text output, 2 for JSON output\n");
        return 1;
    }
    FILE *input_fd = fopen(argv[2],"r");
    if (!input_fd) {
        fprintf(stderr, "error opening file\n");
        return 1;
    }
    thisone = gift_card_reader(input_fd);
    if (argv[1][0] == '1') print_gift_card_info(thisone);
    else if (argv[1][0] == '2') gift_card_json(thisone);

    return 0;
}
#endif
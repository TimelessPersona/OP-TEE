
#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>


#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

struct ta_attrs
{
    TEEC_Context ctx;
    TEEC_Session sess;
};

void prepare_ta_session(struct ta_attrs *ta)
{
    TEEC_UUID uuid = TA_TEEencrypt_UUID;
    uint32_t origin;
    TEEC_Result res;

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ta->ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "\nTEEC_InitializeContext failed with code 0x%x\n", res);

    /* Open a session with the TA */
    res = TEEC_OpenSession(&ta->ctx, &ta->sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "\nTEEC_Opensession failed with code 0x%x origin 0x%x\n", res, origin);
}

void terminate_tee_session(struct ta_attrs *ta)
{
    TEEC_CloseSession(&ta->sess);
    TEEC_FinalizeContext(&ta->ctx);
}

void prepare_op(TEEC_Operation *op, char *in, size_t in_sz, char *out, size_t out_sz)
{
    memset(op, 0, sizeof(*op));

    op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                      TEEC_MEMREF_TEMP_OUTPUT,
                                      TEEC_NONE, TEEC_NONE);
    op->params[0].tmpref.buffer = in;
    op->params[0].tmpref.size = in_sz;
    op->params[1].tmpref.buffer = out;
    op->params[1].tmpref.size = out_sz;
}

void rsa_gen_keys(struct ta_attrs *ta)
{
    TEEC_Result res;

    res = TEEC_InvokeCommand(&ta->sess, TA_RSA_CMD_GENKEYS, NULL, NULL);
    if (res != TEEC_SUCCESS)
        errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_GENKEYS) failed %#x\n", res);
    printf("\n=========== Keys already generated. ==========\n");
}

void rsa_encrypt(struct ta_attrs *ta, char *in, size_t in_sz, char *out, size_t out_sz)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;
    printf("\n============ RSA ENCRYPT CA SIDE ============\n");
    prepare_op(&op, in, in_sz, out, out_sz);

    res = TEEC_InvokeCommand(&ta->sess, TA_RSA_CMD_ENCRYPT,
                             &op, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_ENCRYPT) failed 0x%x origin 0x%x\n",
             res, origin);
    printf("\nThe text sent was encrypted: %s\n", out);
}


int main(int argc, char** argv)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	// file pointer set	
	FILE *fp;
	

	uint32_t err_origin;
	// text arrays	
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	char key[2] = {0};
	int len=64;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;

	if (strcmp(argv[0], "TEEencrypt") == 0) {
		if (strcmp(argv[1], "-e") == 0 && strcmp(argv[3], "Caesar") == 0) {
			// encryption
			fp = fopen(argv[2], "r");
			fgets(plaintext, sizeof(plaintext), fp);
			
			memcpy(op.params[0].tmpref.buffer, plaintext, len);
			printf("%s\n", op.params[0].tmpref.buffer);
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op, 				&err_origin);
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, 							&err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
					res, err_origin);
			memcpy(ciphertext, op.params[0].tmpref.buffer, len);
			fclose(fp);
			fp = fopen("Ciphertext.txt", "w");
			fprintf(fp, "%s", ciphertext);
			printf("Ciphertext : %s\n", ciphertext);
			fclose(fp);

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op, 							&err_origin);
			fp = fopen("enc_key.txt", "w");
			fprintf(fp, op.params[0].tmpref.buffer);
			fclose(fp);
		}
		else if (strcmp(argv[1], "-e") == 0 && strcmp(argv[3], "RSA") == 0) {
			struct ta_attrs ta;

                	prepare_ta_session(&ta);

                	rsa_gen_keys(&ta);
                	rsa_encrypt(&ta, plaintext, RSA_MAX_PLAIN_LEN_1024, ciphertext, 			RSA_CIPHER_LEN_1024);
                	if (fp = fopen("ciphertext.txt", "w"))
                	{
                    	fprintf(fp, ciphertext);
                    	fclose(fp);
                	}

                	terminate_tee_session(&ta);

		}
		else if (strcmp(argv[1], "-d") == 0) {
			// decryption

			fp = fopen(argv[3], "r");
			fgets(key, sizeof(key), fp);
			memcpy(op.params[0].tmpref.buffer, key, sizeof(key));
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_DEC, &op,
						&err_origin);

			fclose(fp);

			fp = fopen(argv[2], "r");
			fgets(ciphertext, sizeof(ciphertext), fp);
			memcpy(op.params[0].tmpref.buffer, ciphertext, len);
			printf("%s\n", op.params[0].tmpref.buffer);
			
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, 							&err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
					res, err_origin);
			memcpy(plaintext, op.params[0].tmpref.buffer, len);
			fclose(fp);
			fp = fopen("Plaintext.txt", "w");
			fprintf(fp, "%s", plaintext);
			printf("Plaintext : %s\n", plaintext);
			fclose(fp);
		}
	}
	

	
	
	
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op, &err_origin);

	/*
	 * TA_HELLO_WORLD_CMD_INC_VALUE is the actual function in the TA to be
	 * called.
	 */
	//printf("Invoking TA to increment %d\n", op.params[0].value.a);
	/*res = TEEC_InvokeCommand(&sess, TA_HELLO_WORLD_CMD_INC_VALUE, &op,
				 &err_origin);*/
	

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}

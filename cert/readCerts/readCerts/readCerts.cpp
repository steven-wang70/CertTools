// readCerts.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include <stdarg.h>

#include "openssl/bio.h"
#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/pem.h"
#include "openssl/pkcs12.h"

static int dump_certs_p12(BIO *out, PKCS12 *p12, char *pass);
static int dump_certs_bags(BIO *out, STACK_OF(PKCS12_SAFEBAG) *bags);
static int dump_certs_bag(BIO *out, PKCS12_SAFEBAG *bags);
static void print_hex(BIO *out, unsigned char *buf, int len);
static int dump_cert_text(BIO *out, X509 *x);

BIO *bio_err = NULL;
BIO *bio_out = NULL;

const int DEFAULT_PASS_LENGTH = -1;
const int DUMP_SUCCESS = 1;
const int DUMP_FAILED = 0;

#if defined(_WIN64)
// Workaround methods on Windows because it could not print to BIO of OpenSSL. 
// Since this is not the focus, I prefer to workaround it temporarily.
// The OpenSSL DLL is not built in the same verion of this tool, which may be the cause.

static int WORKAROUND_BIO_puts(BIO *out, const char *buffer)
{
	if (out == bio_out)
	{
		fputs(buffer, stdout);
	}
	else
	{
		fputs(buffer, stderr);
	}

	return 0;
}

static int WORKAROUND_BIO_printf(BIO *out, const char *format, ...)
{
	char buffer[1000];

	va_list args;
	va_start(args, format);
	vsprintf_s(buffer, format, args);
	va_end(args);

	return WORKAROUND_BIO_puts(out, buffer);
}
#elif defined(__linux__)
#define WORKAROUND_BIO_printf BIO_printf
#define WORKAROUND_BIO_puts BIO_puts
#endif

// In this test application, for simplicity, we are using a single password for all challenges.
int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		fprintf(stderr, "Usage: readCerts <path.p12> <password>");
		return 1;
	}

	char *infile = argv[1];
	char *password = argv[2];

	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

	// Without adding this method call, calling to PKCS12_verify_mac() will fail.
	OpenSSL_add_all_algorithms();

	// Open the .p12 file.
    BIO *in = BIO_new_file(infile, "rb");
    if (!in) {
        WORKAROUND_BIO_printf(bio_err, "Error opening input file %s\n",
                   infile ? infile : "<stdin>");
        perror(infile);
        return 1;
    }

	PKCS12 *p12 = d2i_PKCS12_bio(in, NULL);
    if (!p12) {
        ERR_print_errors(bio_err);
		return 2;
    }

	// MAC verify
	if (!PKCS12_verify_mac(p12, password, DEFAULT_PASS_LENGTH))	{
		// Try again without password
		if (!PKCS12_verify_mac(p12, NULL, 0)) {
			WORKAROUND_BIO_printf(bio_err, "Mac verify error: invalid password?\n");
			ERR_print_errors(bio_err);
			return 4;
		}
	}
	WORKAROUND_BIO_printf(bio_err, "MAC verified OK\n");

	// Traverse p12 keystore to dump certificates.
	if (!dump_certs_p12(bio_out, p12, password)) {
        WORKAROUND_BIO_printf(bio_err, "Error outputting certificates\n");
        ERR_print_errors(bio_err);
		return 5;
    }

	BIO_free(in);
    return 0;
}

// iterate PKCS12_SAFEBAG stacks in the p12 store.
static int dump_certs_p12(BIO *out, PKCS12 *p12, char *pass)
{
    STACK_OF(PKCS7) *asafes = NULL;
    int ret = DUMP_FAILED;

    if (!(asafes = PKCS12_unpack_authsafes(p12)))
        return DUMP_FAILED;

    for (int i = 0; i < sk_PKCS7_num(asafes); i++) {
		PKCS7 *p7 = sk_PKCS7_value(asafes, i);
		STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
		int bagnid = OBJ_obj2nid(p7->type);

        if (bagnid == NID_pkcs7_data) {
            bags = PKCS12_unpack_p7data(p7);
        } else if (bagnid == NID_pkcs7_encrypted) {
            bags = PKCS12_unpack_p7encdata(p7, pass, DEFAULT_PASS_LENGTH);
		}
		else {
			continue;
		}

        if (!bags) goto err;

		// Found a stack of PKCS12_SAFEBAG. Dive into it for 
        if (!dump_certs_bags(out, bags)) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            goto err;
        }

        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    }

    ret = DUMP_SUCCESS;

 err:

	if (asafes) sk_PKCS7_pop_free(asafes, PKCS7_free);
    return ret;
}

// Iterate a PKCS12_SAFEBAG stack.
static int dump_certs_bags(BIO *out, STACK_OF(PKCS12_SAFEBAG) *bags)
{
    for (int i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
		if (!dump_certs_bag(out, sk_PKCS12_SAFEBAG_value(bags, i))) {
			return DUMP_FAILED;
		}
    }

    return DUMP_SUCCESS;
}

// Dump a single PKCS12_SAFEBAG.
static int dump_certs_bag(BIO *out, PKCS12_SAFEBAG *bag)
{
	// We care only cert bag.
	if (M_PKCS12_bag_type(bag) == NID_certBag)
	{
		if (M_PKCS12_cert_bag_type(bag) != NID_x509Certificate) {
			return DUMP_FAILED;
		}

		X509 *x509 = PKCS12_certbag2x509(bag);
		if (!x509) return DUMP_FAILED;

		dump_cert_text(out, x509);
		X509_free(x509);
	}

	return DUMP_SUCCESS;
}

// Dump a X509 certificate.
static int dump_cert_text(BIO *out, X509 *x)
{
	char *p;
	WORKAROUND_BIO_puts(out, "\nCertificate:\n");

	p = X509_NAME_oneline(X509_get_subject_name(x), NULL, 0);
	WORKAROUND_BIO_printf(out, "subject=%s\n", p);
	OPENSSL_free(p);

	p = X509_NAME_oneline(X509_get_issuer_name(x), NULL, 0);
	WORKAROUND_BIO_printf(out, "issuer=%s\n", p);
	OPENSSL_free(p);

	int self_signed = X509_verify(x, X509_get_pubkey(x));
	WORKAROUND_BIO_printf(out, "Self Signed: %s\n", self_signed ? "True" : "False");

	// Finger print
	unsigned int length;
	unsigned char md[EVP_MAX_MD_SIZE];
	const EVP_MD *fdig = EVP_sha256();

	if (!X509_digest(x, fdig, md, &length)) {
		WORKAROUND_BIO_printf(bio_err, "out of memory\n");
		return DUMP_FAILED;
	}
	WORKAROUND_BIO_printf(out, "%s Fingerprint=", OBJ_nid2sn(EVP_MD_type(fdig)));
	print_hex(out, md, length);
	WORKAROUND_BIO_puts(out, "\n");

	return DUMP_SUCCESS;
}

// Print hex values in format XX XX XX XX
static void print_hex(BIO *out, unsigned char *buf, int len)
{
	for (int i = 0; i < len; i++) {
		WORKAROUND_BIO_printf(out, "%02X ", buf[i]);
	}
}

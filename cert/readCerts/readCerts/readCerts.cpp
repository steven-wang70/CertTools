// readCerts.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <stdarg.h>
#include <sstream>
#include <iostream>

#include "openssl/bio.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

int dump_certs_keys_p12(BIO *out, PKCS12 *p12, char *pass, int passlen, char *pempass);
int dump_certs_pkeys_bags(BIO *out, STACK_OF(PKCS12_SAFEBAG) *bags,
	char *pass, int passlen, char *pempass);
int dump_certs_pkeys_bag(BIO *out, PKCS12_SAFEBAG *bags, char *pass,
                         int passlen, char *pempass);
int print_attribs(BIO *out, STACK_OF(X509_ATTRIBUTE) *attrlst,
                  const char *name);
void hex_prin(BIO *out, unsigned char *buf, int len);
int alg_print(BIO *x, X509_ALGOR *alg);
int dump_cert_text(BIO *out, X509 *x);

BIO *bio_err = NULL;
BIO *bio_out = NULL;
const EVP_CIPHER *enc;

std::stringstream outs;
std::stringstream errs;

int WORKAROUND_BIO_printf(BIO *out, const char *format, ...)
{
	char buffer[1000];

	va_list args;
	va_start(args, format);
	vsprintf_s(buffer, format, args);
	va_end(args);

	if (out == bio_out)
	{
		outs << buffer;
	}
	else
	{
		errs << buffer;
	}

	return 0;
}

int WORKAROUND_BIO_puts(BIO *out, const char *buffer)
{
	if (out == bio_out)
	{
		outs << buffer;
	}
	else
	{
		errs << buffer;
	}

	return 0;
}

int main()
{
	const char *infile = "D:\\steven\\gitsrc\\isara\\cert\\certificate.pfx";
	char password[80] = "123456";
	int options = 0;

	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);


	// Without add this method call, call to PKCS12_verify_mac() will fail.
	OpenSSL_add_all_algorithms();

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

/*    if (!password && EVP_read_pw_string(password, sizeof(password), "Enter Import Password:",
                              0)) {
        WORKAROUND_BIO_printf(bio_err, "Can't read Password\n");
		return 3;
    }
*/
	/* If we enter empty password try no password first */
	if (!password[0] && PKCS12_verify_mac(p12, NULL, 0)) {
	} else if (!PKCS12_verify_mac(p12, password, -1)) {
		WORKAROUND_BIO_printf(bio_err, "Mac verify error: invalid password?\n");
		ERR_print_errors(bio_err);
		return 4;
	}
	WORKAROUND_BIO_printf(bio_err, "MAC verified OK\n");

    if (!dump_certs_keys_p12(bio_out, p12, password, -1, password)) {
        WORKAROUND_BIO_printf(bio_err, "Error outputting keys and certificates\n");
        ERR_print_errors(bio_err);
		return 5;
    }


//	fflush(stdout);
    BIO_free(in);

    return 0;
}


int dump_certs_keys_p12(BIO *out, PKCS12 *p12, char *pass, int passlen, char *pempass)
{
    STACK_OF(PKCS7) *asafes = NULL;
    STACK_OF(PKCS12_SAFEBAG) *bags;
    int i, bagnid;
    int ret = 0;
    PKCS7 *p7;

    if (!(asafes = PKCS12_unpack_authsafes(p12)))
        return 0;
	int num = sk_PKCS7_num(asafes);
    for (i = 0; i < sk_PKCS7_num(asafes); i++) {
        p7 = sk_PKCS7_value(asafes, i);
        bagnid = OBJ_obj2nid(p7->type);
        if (bagnid == NID_pkcs7_data) {
            bags = PKCS12_unpack_p7data(p7);
        } else if (bagnid == NID_pkcs7_encrypted) {
            bags = PKCS12_unpack_p7encdata(p7, pass, passlen);
        } else
            continue;
        if (!bags)
            goto err;
        if (!dump_certs_pkeys_bags(out, bags, pass, passlen, pempass)) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            goto err;
        }
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        bags = NULL;
    }
    ret = 1;

 err:

    if (asafes)
        sk_PKCS7_pop_free(asafes, PKCS7_free);
    return ret;
}

int dump_certs_pkeys_bags(BIO *out, STACK_OF(PKCS12_SAFEBAG) *bags,
	char *pass, int passlen, char *pempass)
{
	int num = sk_PKCS12_SAFEBAG_num(bags);
    int i;
    for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
        if (dump_certs_pkeys_bag(out,
                                  sk_PKCS12_SAFEBAG_value(bags, i),
                                  pass, passlen, pempass))
            return 0;
    }
    return 1;
}

int dump_certs_pkeys_bag(BIO *out, PKCS12_SAFEBAG *bag, char *pass,
                         int passlen, char *pempass)
{
    EVP_PKEY *pkey;
    PKCS8_PRIV_KEY_INFO *p8;
    X509 *x509;
    int ret = 0;

    switch (M_PKCS12_bag_type(bag)) {
    case NID_keyBag:
        print_attribs(out, bag->attrib, "Bag Attributes");
        p8 = bag->value.keybag;
        if (!(pkey = EVP_PKCS82PKEY(p8)))
            return 0;
        print_attribs(out, p8->attributes, "Key Attributes");
        ret = PEM_write_bio_PrivateKey(out, pkey, enc, NULL, 0, NULL, pempass);
        EVP_PKEY_free(pkey);
        break;

    case NID_pkcs8ShroudedKeyBag:
        print_attribs(out, bag->attrib, "Bag Attributes");
        if (!(p8 = PKCS12_decrypt_skey(bag, pass, passlen)))
            return 0;
        if (!(pkey = EVP_PKCS82PKEY(p8))) {
            PKCS8_PRIV_KEY_INFO_free(p8);
            return 0;
        }
        print_attribs(out, p8->attributes, "Key Attributes");
        PKCS8_PRIV_KEY_INFO_free(p8);
        ret = PEM_write_bio_PrivateKey(out, pkey, enc, NULL, 0, NULL, pempass);
        EVP_PKEY_free(pkey);
        break;

    case NID_certBag:
        print_attribs(out, bag->attrib, "Bag Attributes");
        if (M_PKCS12_cert_bag_type(bag) != NID_x509Certificate)
            return 1;
        if (!(x509 = PKCS12_certbag2x509(bag)))
            return 0;
        dump_cert_text(out, x509);
        ret = PEM_write_bio_X509(out, x509);
        X509_free(x509);
        break;

    case NID_safeContentsBag:
        print_attribs(out, bag->attrib, "Bag Attributes");
        return dump_certs_pkeys_bags(out, bag->value.safes, pass,
                                     passlen, pempass);

    default:
        WORKAROUND_BIO_printf(bio_err, "Warning unsupported bag type: ");
        i2a_ASN1_OBJECT(bio_err, bag->type);
        WORKAROUND_BIO_printf(bio_err, "\n");
        return 1;
        break;
    }
    return ret;
}


int print_attribs(BIO *out, STACK_OF(X509_ATTRIBUTE) *attrlst,
                  const char *name)
{
    X509_ATTRIBUTE *attr;
    ASN1_TYPE *av;
    char *value;
    int i, attr_nid;
    if (!attrlst) {
        WORKAROUND_BIO_printf(out, "%s: <No Attributes>\n", name);
        return 1;
    }
    if (!sk_X509_ATTRIBUTE_num(attrlst)) {
        WORKAROUND_BIO_printf(out, "%s: <Empty Attributes>\n", name);
        return 1;
    }
    WORKAROUND_BIO_printf(out, "%s\n", name);
    for (i = 0; i < sk_X509_ATTRIBUTE_num(attrlst); i++) {
        attr = sk_X509_ATTRIBUTE_value(attrlst, i);
        attr_nid = OBJ_obj2nid(attr->object);
        WORKAROUND_BIO_printf(out, "    ");
        if (attr_nid == NID_undef) {
            i2a_ASN1_OBJECT(out, attr->object);
            WORKAROUND_BIO_printf(out, ": ");
        } else
            WORKAROUND_BIO_printf(out, "%s: ", OBJ_nid2ln(attr_nid));

        if (sk_ASN1_TYPE_num(attr->value.set)) {
            av = sk_ASN1_TYPE_value(attr->value.set, 0);
            switch (av->type) {
            case V_ASN1_BMPSTRING:
                value = OPENSSL_uni2asc(av->value.bmpstring->data,
                                        av->value.bmpstring->length);
                WORKAROUND_BIO_printf(out, "%s\n", value);
                OPENSSL_free(value);
                break;

            case V_ASN1_OCTET_STRING:
                hex_prin(out, av->value.octet_string->data,
                         av->value.octet_string->length);
                WORKAROUND_BIO_printf(out, "\n");
                break;

            case V_ASN1_BIT_STRING:
                hex_prin(out, av->value.bit_string->data,
                         av->value.bit_string->length);
                WORKAROUND_BIO_printf(out, "\n");
                break;

            default:
                WORKAROUND_BIO_printf(out, "<Unsupported tag %d>\n", av->type);
                break;
            }
        } else
            WORKAROUND_BIO_printf(out, "<No Values>\n");
    }
    return 1;
}

void hex_prin(BIO *out, unsigned char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++)
        WORKAROUND_BIO_printf(out, "%02X ", buf[i]);
}


int alg_print(BIO *x, X509_ALGOR *alg)
{
	return 1;
}
//	int pbenid, aparamtype;
//	ASN1_OBJECT *aoid;
//	void *aparam;
//	PBEPARAM *pbe = NULL;
//
//	X509_ALGOR_get0(&aoid, &aparamtype, &aparam, alg);
//
//	pbenid = OBJ_obj2nid(aoid);
//
//	WORKAROUND_BIO_printf(x, "%s", OBJ_nid2ln(pbenid));
//
//	/*
//	* If PBE algorithm is PBES2 decode algorithm parameters
//	* for additional details.
//	*/
//	if (pbenid == NID_pbes2) {
//		PBE2PARAM *pbe2 = NULL;
//		int encnid;
//		if (aparamtype == V_ASN1_SEQUENCE)
//			pbe2 = ASN1_item_unpack(aparam, ASN1_ITEM_rptr(PBE2PARAM));
//		if (pbe2 == NULL) {
//			WORKAROUND_BIO_puts(x, "<unsupported parameters>");
//			goto done;
//		}
//		X509_ALGOR_get0(&aoid, &aparamtype, &aparam, pbe2->keyfunc);
//		pbenid = OBJ_obj2nid(aoid);
//		X509_ALGOR_get0(&aoid, NULL, NULL, pbe2->encryption);
//		encnid = OBJ_obj2nid(aoid);
//		WORKAROUND_BIO_printf(x, ", %s, %s", OBJ_nid2ln(pbenid),
//			OBJ_nid2sn(encnid));
//		/* If KDF is PBKDF2 decode parameters */
//		if (pbenid == NID_id_pbkdf2) {
//			PBKDF2PARAM *kdf = NULL;
//			int prfnid;
//			if (aparamtype == V_ASN1_SEQUENCE)
//				kdf = ASN1_item_unpack(aparam, ASN1_ITEM_rptr(PBKDF2PARAM));
//			if (kdf == NULL) {
//				WORKAROUND_BIO_puts(x, "<unsupported parameters>");
//				goto done;
//			}
//
//			if (kdf->prf == NULL) {
//				prfnid = NID_hmacWithSHA1;
//			}
//			else {
//				X509_ALGOR_get0(&aoid, NULL, NULL, kdf->prf);
//				prfnid = OBJ_obj2nid(aoid);
//			}
//			WORKAROUND_BIO_printf(x, ", Iteration %ld, PRF %s",
//				ASN1_INTEGER_get(kdf->iter), OBJ_nid2sn(prfnid));
//			PBKDF2PARAM_free(kdf);
//		}
//		PBE2PARAM_free(pbe2);
//	}
//	else {
//		if (aparamtype == V_ASN1_SEQUENCE)
//			pbe = ASN1_item_unpack(aparam, ASN1_ITEM_rptr(PBEPARAM));
//		if (pbe == NULL) {
//			WORKAROUND_BIO_puts(x, "<unsupported parameters>");
//			goto done;
//		}
//		WORKAROUND_BIO_printf(x, ", Iteration %ld", ASN1_INTEGER_get(pbe->iter));
//		PBEPARAM_free(pbe);
//	}
//done:
//	WORKAROUND_BIO_puts(x, "\n");
//	return 1;
//}

int dump_cert_text(BIO *out, X509 *x)
{
	char *p;

	p = X509_NAME_oneline(X509_get_subject_name(x), NULL, 0);
	WORKAROUND_BIO_puts(out, "subject=");
	WORKAROUND_BIO_puts(out, p);
	OPENSSL_free(p);

	p = X509_NAME_oneline(X509_get_issuer_name(x), NULL, 0);
	WORKAROUND_BIO_puts(out, "\nissuer=");
	WORKAROUND_BIO_puts(out, p);
	WORKAROUND_BIO_puts(out, "\n");
	OPENSSL_free(p);

	int self_signed = X509_verify(x, X509_get_pubkey(x));
	WORKAROUND_BIO_printf(out, "Self Signed: %s\n ", self_signed ? "True" : "False");

	// Finger print
	int j;
	unsigned int n;
	unsigned char md[EVP_MAX_MD_SIZE];
	const EVP_MD *fdig = EVP_sha256();

	if (!X509_digest(x, fdig, md, &n)) {
		WORKAROUND_BIO_printf(bio_err, "out of memory\n");
		return 1;
	}
	WORKAROUND_BIO_printf(out, "%s Fingerprint=",
		OBJ_nid2sn(EVP_MD_type(fdig)));
	for (j = 0; j < (int)n; j++) {
		WORKAROUND_BIO_printf(out, "%02X%c", md[j], (j + 1 == (int)n)
			? '\n' : ':');
	}


	return 0;
}

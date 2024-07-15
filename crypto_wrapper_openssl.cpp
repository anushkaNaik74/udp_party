#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <typeinfo>
#include "utils.h"
#include "crypto_wrapper.h"

#ifdef OPENSSL
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/ossl_typ.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#ifdef WIN
#pragma comment (lib, "libcrypto.lib")
#pragma comment (lib, "openssl.lib")
#endif // #ifdef WIN

static constexpr size_t PEM_BUFFER_SIZE_BYTES	= 10000;
static constexpr size_t HASH_SIZE_BYTES			= 32; //To be define by the participants
static constexpr size_t IV_SIZE_BYTES			= 12; //To be define by the participants
static constexpr size_t GMAC_SIZE_BYTES			= 16; //To be define by the participants


bool CryptoWrapper::hmac_SHA256(IN const BYTE* key, size_t keySizeBytes, IN const BYTE* message, IN size_t messageSizeBytes, OUT BYTE* macBuffer, IN size_t macBufferSizeBytes)
{
	EVP_MD_CTX* mdctx = NULL;
	EVP_PKEY* pkey = NULL;
	size_t macLength = 0;
	bool result = false;

	// Create a new digest context
	mdctx = EVP_MD_CTX_new();
	if (mdctx == NULL) {
		goto err;
	}

	// Create a new raw private key
	pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, keySizeBytes);
	if (pkey == NULL) {
		goto err;
	}

	// Initialize the digest sign context
	if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
		goto err;
	}

	// Update the digest with the message
	if (EVP_DigestSignUpdate(mdctx, message, messageSizeBytes) != 1) {
		goto err;
	}

	// Determine the length of the resulting HMAC
	if (EVP_DigestSignFinal(mdctx, NULL, &macLength) != 1) {
		goto err;
	}

	// Check if the provided macBuffer is large enough
	if (macBufferSizeBytes < macLength) {
		goto err;
	}

	// Finalize the digest sign operation and get the HMAC
	if (EVP_DigestSignFinal(mdctx, macBuffer, &macLength) != 1) {
		goto err;
	}

	result = true;

err:
	if (mdctx) EVP_MD_CTX_free(mdctx);
	if (pkey) EVP_PKEY_free(pkey);

	return result;
}


bool CryptoWrapper::deriveKey_HKDF_SHA256(const BYTE* salt, size_t saltSizeBytes, const BYTE* secretMaterial, size_t secretMaterialSizeBytes, const BYTE* context, size_t contextSizeBytes, BYTE* outputBuffer, size_t outputBufferSizeBytes)
{
	bool ret = false;
	EVP_PKEY_CTX* pctx = NULL;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (pctx == NULL) {
		printf("Failed to get HKDF context\n");
		goto err;
	}

	if (EVP_PKEY_derive_init(pctx) <= 0) {
		printf("EVP_PKEY_derive_init failed\n");
		goto err;
	}

	if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) <= 0) {
		printf("EVP_PKEY_CTX_hkdf_mode failed\n");
		goto err;
	}

	if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
		printf("EVP_PKEY_CTX_set_hkdf_md failed\n");
		goto err;
	}

	if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltSizeBytes) <= 0) {
		printf("EVP_PKEY_CTX_set1_hkdf_salt failed\n");
		goto err;
	}

	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secretMaterial, secretMaterialSizeBytes) <= 0) {
		printf("EVP_PKEY_CTX_set1_hkdf_key failed\n");
		goto err;
	}

	if (EVP_PKEY_CTX_add1_hkdf_info(pctx, context, contextSizeBytes) <= 0) {
		printf("EVP_PKEY_CTX_add1_hkdf_info failed\n");
		goto err;
	}

	if (EVP_PKEY_derive(pctx, outputBuffer, &outputBufferSizeBytes) <= 0) {
		printf("EVP_PKEY_derive failed\n");
		goto err;
	}

	ret = true;

err:
	if (pctx) EVP_PKEY_CTX_free(pctx);

	return ret;
}

size_t CryptoWrapper::getCiphertextSizeAES_GCM256(IN size_t plaintextSizeBytes)
{
	return plaintextSizeBytes + IV_SIZE_BYTES + GMAC_SIZE_BYTES;
}

size_t CryptoWrapper::getPlaintextSizeAES_GCM256(IN size_t ciphertextSizeBytes)
{
	return (ciphertextSizeBytes > IV_SIZE_BYTES + GMAC_SIZE_BYTES ? ciphertextSizeBytes - IV_SIZE_BYTES - GMAC_SIZE_BYTES : 0);
}

bool CryptoWrapper::encryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
	IN const BYTE* plaintext, IN size_t plaintextSizeBytes,
	IN const BYTE* aad, IN size_t aadSizeBytes,
	OUT BYTE* ciphertextBuffer, IN size_t ciphertextBufferSizeBytes, OUT size_t* pCiphertextSizeBytes)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
	{
		std::cerr << "Failed to create AES-GCM encryption context" << std::endl;
		return false;
	}

	int len = 0;
	int ciphertextLen = 0;
	BYTE iv[EVP_MAX_IV_LENGTH];

	if (plaintext == nullptr || plaintextSizeBytes == 0 || aad == nullptr || aadSizeBytes == 0 || ciphertextBuffer == nullptr || ciphertextBufferSizeBytes == 0)
	{
		std::cerr << "Invalid input parameters for encryption" << std::endl;
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// Generate IV
	if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1)
	{
		std::cerr << "Error generating IV\n";
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// Initialize encryption operation
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
	{
		std::cerr << "EVP_EncryptInit_ex failed" << std::endl;
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// Set IV length
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE_BYTES, nullptr) != 1)
	{
		std::cerr << "EVP_CIPHER_CTX_ctrl for setting IV length failed" << std::endl;
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// Initialize key and IV
	if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1)
	{
		std::cerr << "EVP_EncryptInit_ex with key and IV failed" << std::endl;
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// Provide AAD (Additional Authenticated Data)
	if (aad != nullptr && aadSizeBytes > 0)
	{
		if (EVP_EncryptUpdate(ctx, nullptr, &len, aad, aadSizeBytes) != 1)
		{
			std::cerr << "EVP_EncryptUpdate for AAD failed" << std::endl;
			EVP_CIPHER_CTX_free(ctx);
			return false;
		}
	}

	// Encrypt plaintext
	if (EVP_EncryptUpdate(ctx, ciphertextBuffer, &len, plaintext, plaintextSizeBytes) != 1)
	{
		std::cerr << "EVP_EncryptUpdate for plaintext failed" << std::endl;
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	ciphertextLen = len;

	// Finalize encryption (get the tag)
	if (EVP_EncryptFinal_ex(ctx, ciphertextBuffer + len, &len) != 1)
	{
		std::cerr << "EVP_EncryptFinal_ex failed" << std::endl;
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	ciphertextLen += len;

	// Get the tag
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GMAC_SIZE_BYTES, ciphertextBuffer + ciphertextLen) != 1)
	{
		std::cerr << "EVP_CIPHER_CTX_ctrl for getting tag failed" << std::endl;
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	ciphertextLen += GMAC_SIZE_BYTES;

	*pCiphertextSizeBytes = ciphertextLen;

	EVP_CIPHER_CTX_free(ctx);

	return true;
}

bool CryptoWrapper::decryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
	IN const BYTE* ciphertext, IN size_t ciphertextSizeBytes,
	IN const BYTE* aad, IN size_t aadSizeBytes,
	OUT BYTE* plaintextBuffer, IN size_t plaintextBufferSizeBytes, OUT size_t* pPlaintextSizeBytes)
{
	if (key == nullptr || ciphertext == nullptr || plaintextBuffer == nullptr ||
		ciphertextSizeBytes < (IV_SIZE_BYTES + GMAC_SIZE_BYTES) || plaintextBufferSizeBytes == 0)
	{
		std::cerr << "Invalid input parameters for decryption" << std::endl;
		return false;
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
	{
		std::cerr << "Failed to create AES-GCM decryption context" << std::endl;
		return false;
	}

	int len = 0;
	int plaintextLen = 0;
	int ret = 0;

	// Initialize the decryption operation
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
	{
		std::cerr << "EVP_DecryptInit_ex failed" << std::endl;
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// Set IV length
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE_BYTES, nullptr))
	{
		std::cerr << "EVP_CIPHER_CTX_ctrl for setting IV length failed" << std::endl;
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// Initialize key and IV
	if (!EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, ciphertext))
	{
		std::cerr << "EVP_DecryptInit_ex with key and IV failed" << std::endl;
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// Provide AAD (Additional Authenticated Data)
	if (aad != nullptr && aadSizeBytes > 0)
	{
		if (!EVP_DecryptUpdate(ctx, nullptr, &len, aad, aadSizeBytes))
		{
			std::cerr << "EVP_DecryptUpdate for AAD failed" << std::endl;
			EVP_CIPHER_CTX_free(ctx);
			return false;
		}
	}

	// Provide ciphertext and obtain plaintext
	if (!EVP_DecryptUpdate(ctx, plaintextBuffer, &len, ciphertext + IV_SIZE_BYTES, ciphertextSizeBytes - IV_SIZE_BYTES - GMAC_SIZE_BYTES))
	{
		std::cerr << "EVP_DecryptUpdate for ciphertext failed" << std::endl;
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	plaintextLen = len;

	// Set expected tag value
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GMAC_SIZE_BYTES, (void*)(ciphertext + ciphertextSizeBytes - GMAC_SIZE_BYTES)))
	{
		std::cerr << "EVP_CIPHER_CTX_ctrl for setting tag failed" << std::endl;
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// Finalize the decryption
	ret = EVP_DecryptFinal_ex(ctx, plaintextBuffer + len, &len);
	if (ret <= 0)
	{
		std::cerr << "EVP_DecryptFinal_ex failed or authentication failed: " << ret << std::endl;
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	plaintextLen += len;

	// Get the plaintext size
	if (pPlaintextSizeBytes != nullptr)
	{
		*pPlaintextSizeBytes = plaintextLen;
	}

	EVP_CIPHER_CTX_free(ctx);
	return true;
}





bool CryptoWrapper::readRSAKeyFromFile(IN const char* keyFilename, IN const char* filePassword, OUT KeypairContext** pKeyContext)
{
	EVP_PKEY* key = NULL;
	FILE* keyFile = NULL;
	errno_t err = fopen_s(&keyFile, keyFilename, "r");
	if (err != 0 || keyFile == NULL)
	{
		std::cerr << "Error opening key file: " << keyFilename << std::endl;
		return false;
	}

	// Read private key from file
	key = PEM_read_PrivateKey(keyFile, NULL, NULL, (void*)filePassword);
	fclose(keyFile);

	if (!key)
	{
		std::cerr << "Error reading private key from file" << std::endl;
		return false;
	}

	// Create a context for the key
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, NULL);
	if (!ctx)
	{
		std::cerr << "Error creating key context" << std::endl;
		EVP_PKEY_free(key);
		return false;
	}

	*pKeyContext = ctx;
	EVP_PKEY_free(key); // Free the EVP_PKEY as it's no longer needed
	return true;
}





bool CryptoWrapper::signMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* privateKeyContext, OUT BYTE* signatureBuffer, IN size_t signatureBufferSizeBytes)
{
	return false;
}


bool CryptoWrapper::verifyMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* publicKeyContext, IN const BYTE* signature, IN size_t signatureSizeBytes, OUT bool* result)
{

	return false;
}


void CryptoWrapper::cleanKeyContext(INOUT KeypairContext** pKeyContext)
{
	if (*pKeyContext != NULL)
	{
		EVP_PKEY_CTX_free(*pKeyContext);
		*pKeyContext = NULL;
	}
}




bool CryptoWrapper::writePublicKeyToPemBuffer(IN KeypairContext* keyContext, OUT BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	return false;
}


bool CryptoWrapper::loadPublicKeyFromPemBuffer(INOUT KeypairContext* context, IN const BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	return false;
}




bool CryptoWrapper::startDh(OUT DhContext** pDhContext, OUT BYTE* publicKeyBuffer, IN size_t publicKeyBufferSizeBytes)
{
	bool ret = false;
	EVP_PKEY_CTX* ctx = NULL;
	EVP_PKEY* params = NULL;
	EVP_PKEY* dhkey = NULL;

	*pDhContext = NULL;
	size_t len = publicKeyBufferSizeBytes;
	EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new(params, NULL);

	// Create parameter generation context
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
	if (!ctx) {
		goto err;
	}

	// Initialize parameter generation
	if (EVP_PKEY_paramgen_init(ctx) <= 0) {
		goto err;
	}

	// Set the length of the prime for DH
	if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, 3072) <= 0) {
		goto err;
	}

	// Generate parameters
	if (EVP_PKEY_paramgen(ctx, &params) <= 0) {
		goto err;
	}

	// Create the key generation context
	if (!key_ctx) {
		goto err;
	}

	// Generate the key pair
	if (EVP_PKEY_keygen_init(key_ctx) <= 0) {
		goto err;
	}
	if (EVP_PKEY_keygen(key_ctx, &dhkey) <= 0) {
		goto err;
	}

	// Extract the public key
	if (EVP_PKEY_get_raw_public_key(dhkey, publicKeyBuffer, &len) <= 0) {
		goto err;
	}

	// Set the DhContext
	*pDhContext = dhkey;

	ret = true;

err:
	if (dhkey != NULL) {
		EVP_PKEY_free(dhkey);
	}
	if (params != NULL) {
		EVP_PKEY_free(params);
	}
	if (ctx != NULL) {
		EVP_PKEY_CTX_free(ctx);
	}

	return ret;
}




bool CreatePeerPublicKey(const BYTE* peerPublicKey, size_t peerPublicKeySizeBytes, EVP_PKEY** genPeerPublicKey)
{
	EVP_PKEY_CTX* ctx = NULL;
	bool ret = false;

	// Create a new context
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
	if (!ctx) {
		goto err;
	}

	// Initialize from public key data
	if (EVP_PKEY_fromdata_init(ctx) <= 0) {
		goto err;
	}

	// Set the public key
	

	ret = true;

err:
	if (ctx) {
		EVP_PKEY_CTX_free(ctx);
	}
	return ret;
}





bool CryptoWrapper::getDhSharedSecret(INOUT DhContext* dhContext, IN const BYTE* peerPublicKey, IN size_t peerPublicKeySizeBytes, OUT BYTE* sharedSecretBuffer, IN size_t sharedSecretBufferSizeBytes)
{
	bool ret = false;
	EVP_PKEY* genPeerPublicKey = NULL;
	EVP_PKEY_CTX* derivationCtx = NULL;

	if (!dhContext || !peerPublicKey || !sharedSecretBuffer) {
		goto err;
	}

	// Create EVP_PKEY from peer's public key
	if (!CreatePeerPublicKey(peerPublicKey, peerPublicKeySizeBytes, &genPeerPublicKey)) {
		goto err;
	}

	// Create a key derivation context
	derivationCtx = EVP_PKEY_CTX_new(dhContext, NULL);
	if (!derivationCtx) {
		goto err;
	}

	// Initialize the key derivation operation
	if (EVP_PKEY_derive_init(derivationCtx) <= 0) {
		goto err;
	}

	// Provide the peer's public key
	if (EVP_PKEY_derive_set_peer(derivationCtx, genPeerPublicKey) <= 0) {
		goto err;
	}

	// Determine the shared secret size
	size_t sslen;
	if (EVP_PKEY_derive(derivationCtx, NULL, &sslen) <= 0) {
		goto err;
	}

	if (sslen > sharedSecretBufferSizeBytes) {
		goto err;
	}

	// Derive the shared secret
	if (EVP_PKEY_derive(derivationCtx, sharedSecretBuffer, &sslen) <= 0) {
		goto err;
	}

	ret = true;

err:
	if (genPeerPublicKey != NULL) {
		EVP_PKEY_free(genPeerPublicKey);
	}
	if (derivationCtx != NULL) {
		EVP_PKEY_CTX_free(derivationCtx);
	}

	return ret;
}



void CryptoWrapper::cleanDhContext(INOUT DhContext** pDhContext)
{
	if (*pDhContext != NULL)
	{
		EVP_PKEY_free(*pDhContext);
		*pDhContext = NULL;
	}
}

X509* loadCertificate(const BYTE* certBuffer, size_t certSizeBytes)
{
	int ret = 0;
	BIO* bio = NULL;
	X509* cert = NULL;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
	{
		printf("BIO_new() fail \n");
		goto err;
	}

	ret = BIO_write(bio, (const void*)certBuffer, (int)certSizeBytes);
	if (ret <= 0)
	{
		printf("BIO_write() fail \n");
		goto err;
	}

	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (cert == NULL)
	{
		printf("PEM_read_bio_X509() fail \n");
		goto err;
	}

err:
	BIO_free(bio);

	return cert;
}

bool CryptoWrapper::checkCertificate(IN const BYTE* cACcertBuffer, IN size_t cACertSizeBytes, IN const BYTE* certBuffer, IN size_t certSizeBytes, IN const char* expectedCN)
{
	int ret = 0;
	X509* userCert = NULL;
	X509* caCert = NULL;


	caCert = loadCertificate(cACcertBuffer, cACertSizeBytes);
	if (caCert == NULL)
	{
		printf("loadCertificate() fail \n");
		goto err;
	}

	userCert = loadCertificate(certBuffer, certSizeBytes);
	if (userCert == NULL)
	{
		printf("loadCertificate() fail \n");
		goto err;
	}

// ...

err:
	X509_free(caCert);
	X509_free(userCert);

	return ret;
}


bool CryptoWrapper::getPublicKeyFromCertificate(IN const BYTE* certBuffer, IN size_t certSizeBytes, OUT KeypairContext** pPublicKeyContext)
{

	return false;
}

#endif // #ifdef OPENSSL

/*
* 
* Usefull links
* -------------------------
* *  
* https://www.intel.com/content/www/us/en/develop/documentation/cpp-compiler-developer-guide-and-reference/top/compiler-reference/intrinsics/intrinsics-for-later-gen-core-proc-instruct-exts/intrinsics-gen-rand-nums-from-16-32-64-bit-ints/rdrand16-step-rdrand32-step-rdrand64-step.html
* https://wiki.openssl.org/index.php/OpenSSL_3.0
* https://www.rfc-editor.org/rfc/rfc3526
* 
* 
* Usefull APIs
* -------------------------
* 
* EVP_MD_CTX_new
* EVP_PKEY_new_raw_private_key
* EVP_DigestSignInit
* EVP_DigestSignUpdate
* EVP_PKEY_CTX_new_id
* EVP_PKEY_derive_init
* EVP_PKEY_CTX_set_hkdf_md
* EVP_PKEY_CTX_set1_hkdf_salt
* EVP_PKEY_CTX_set1_hkdf_key
* EVP_PKEY_derive
* EVP_CIPHER_CTX_new
* EVP_EncryptInit_ex
* EVP_EncryptUpdate
* EVP_EncryptFinal_ex
* EVP_CIPHER_CTX_ctrl
* EVP_DecryptInit_ex
* EVP_DecryptUpdate
* EVP_DecryptFinal_ex
* OSSL_PARAM_BLD_new
* OSSL_PARAM_BLD_push_BN
* EVP_PKEY_CTX_new_from_name
* EVP_PKEY_fromdata_init
* EVP_PKEY_fromdata
* EVP_PKEY_CTX_new
* EVP_PKEY_derive_init
* EVP_PKEY_derive_set_peer
* EVP_PKEY_derive_init
* BIO_new
* BIO_write
* PEM_read_bio_X509
* X509_STORE_new
* X509_STORE_CTX_new
* X509_STORE_add_cert
* X509_verify_cert
* X509_check_host
*
*
*
*/

//
//  RSAKit.m
//  RSAExercise
//
//  Created by _ivanC on 04/02/15.
//  Copyright © 2015 _ivanC. All rights reserved.
//

#import "RSAKit.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C"{
#endif
    
    SecKeyRef createPublicKeyRef(NSString* certPath)
    {
        NSData *certData = [NSData dataWithContentsOfFile:certPath];
        if ([certData length] <= 0)
        {
            return NULL;
        }
        
        SecCertificateRef cert = SecCertificateCreateWithData(NULL, (CFDataRef)certData);
        SecKeyRef key = NULL;
        SecTrustRef trust = NULL;
        SecPolicyRef policy = NULL;
        
        if (cert != NULL)
        {
            policy = SecPolicyCreateBasicX509();
            if (policy)
            {
                if (SecTrustCreateWithCertificates((CFTypeRef)cert, policy, &trust) == noErr)
                {
                    SecTrustResultType result;
                    if (SecTrustEvaluate(trust, &result) == noErr)
                    {
                        key = SecTrustCopyPublicKey(trust);
                    }
                }
            }
        }
        
        if (policy)
        {
            CFRelease(policy);
            policy = NULL;
        }
        
        if (trust)
        {
            CFRelease(trust);
            trust = NULL;
        }
        
        if (cert)
        {
            CFRelease(cert);
            cert = NULL;
        }
        return key;
    }
    
    SecKeyRef createPrivateKeyRef(NSString* certPath, NSString *password)
    {
        NSData *p12Data = [NSData dataWithContentsOfFile:certPath];
        if ([p12Data length] <= 0)
        {
            return NULL;
        }
        
        CFMutableDictionaryRef options = CFDictionaryCreateMutable(kCFAllocatorDefault, 2, NULL, NULL);
        if (password)
        {
            CFDictionaryAddValue(options, kSecImportExportPassphrase, (__bridge const void *)(password));
        }
        
        CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
        OSStatus securityError = SecPKCS12Import((CFDataRef) p12Data,
                                                 (CFDictionaryRef)options, &items);
        
        SecKeyRef privateKeyRef = NULL;
        if (securityError == noErr && CFArrayGetCount(items) > 0)
        {
            CFDictionaryRef identityDict = (CFDictionaryRef)CFArrayGetValueAtIndex(items, 0);
            SecIdentityRef identityApp =
            (SecIdentityRef)CFDictionaryGetValue(identityDict,
                                                 kSecImportItemIdentity);
            
            securityError = SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
            if (securityError != noErr)
            {
                privateKeyRef = NULL;
            }
        }
        
        if (options)
        {
            CFRelease(options);
            options = NULL;
        }
        
        if (items)
        {
            CFRelease(items);
            items = NULL;
        }
        
        return privateKeyRef;
    }
    
#if (TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR)
    NSData* encryptDataRSA(NSData* rawData, SecKeyRef publicKey, SecPadding padding)
    {
        NSData *cipherData = nil;
        
        do
        {
            if ([rawData length] <= 0)
            {
                break;
            }
            
            if (!publicKey)
            {
                break;
            }
            
            size_t cipherBytesSize = SecKeyGetBlockSize(publicKey);
            
            uint8_t *cipherBytes = (uint8_t *)malloc(cipherBytesSize * sizeof(uint8_t));
            memset((void *)cipherBytes, 0x0, cipherBytesSize);
            
            OSStatus encryptCheck = noErr;
            encryptCheck = SecKeyEncrypt(publicKey,
                                         padding,
                                         (const uint8_t *)[rawData bytes],
                                         [rawData length],
                                         cipherBytes,
                                         &cipherBytesSize);
            
            if (encryptCheck == noErr)
            {
                cipherData = [NSData dataWithBytes:cipherBytes length:cipherBytesSize];
            }
            
            if (cipherBytes)
            {
                free(cipherBytes);
                cipherBytes = NULL;
            }
            
        } while (0);
        
        return cipherData;
    }
    
    NSData* decryptDataRSA(NSData* encryptedData, SecKeyRef privateKey, SecPadding padding)
    {
        NSData *plainData = nil;
        
        do
        {
            if ([encryptedData length] <= 0)
            {
                break;
            }
            
            if (!privateKey)
            {
                break;
            }
            
            size_t plainBytesSize = SecKeyGetBlockSize(privateKey);
            
            uint8_t *plainBytes = (uint8_t *)malloc(plainBytesSize * sizeof(uint8_t));
            memset((void *)plainBytes, 0x0, plainBytesSize);
            
            OSStatus encryptCheck = noErr;
            encryptCheck = SecKeyDecrypt(privateKey,
                                         padding,
                                         (const uint8_t *)[encryptedData bytes],
                                         [encryptedData length],
                                         plainBytes,
                                         &plainBytesSize);
            
            if (encryptCheck == noErr)
            {
                plainData = [NSData dataWithBytes:plainBytes length:plainBytesSize];
            }
            
            if (plainBytes)
            {
                free(plainBytes);
                plainBytes = NULL;
            }
            
        } while (0);
        
        return plainData;
    }
    
    NSData* getSignatureBytes(NSData *plainData, SecKeyRef privateKey, SecPadding padding)
    {
        if (plainData == nil || privateKey == nil)
        {
            return nil;
        }
        
        OSStatus sanityCheck = noErr;
        NSData *signedHash = nil;
        
        size_t signedHashBytesSize = SecKeyGetBlockSize(privateKey);
        
        // Malloc a buffer to hold signature.
        uint8_t *signedHashBytes = (uint8_t *)malloc( signedHashBytesSize * sizeof(uint8_t) );
        memset((void *)signedHashBytes, 0x0, signedHashBytesSize);
        
        // Sign
        sanityCheck = SecKeyRawSign(	privateKey,
                                    padding,
                                    (const uint8_t *)[plainData bytes],
                                    [plainData length],
                                    (uint8_t *)signedHashBytes,
                                    &signedHashBytesSize
                                    );
        
        // Build up signed
        if (sanityCheck == noErr)
        {
            signedHash = [NSData dataWithBytes:(const void *)signedHashBytes length:(NSUInteger)signedHashBytesSize];
        }
        
        if (signedHashBytes)
        {
            free(signedHashBytes);
            signedHashBytes = NULL;
        }
        
        return signedHash;
    }
    
    BOOL verifySignature(NSData* plainData, SecKeyRef publicKey, SecPadding padding, NSData* signature)
    {
        if (plainData == nil || publicKey == nil || signature == nil)
        {
            return NO;
        }
        
        // Get the size of the assymetric block.
        size_t signedHashBytesSize = SecKeyGetBlockSize(publicKey);
        
        OSStatus sanityCheck = SecKeyRawVerify(	publicKey,
                                               padding,
                                               (const uint8_t *)[plainData bytes],
                                               [plainData length],
                                               (const uint8_t *)[signature bytes],
                                               signedHashBytesSize
                                               );
        
        return (sanityCheck == noErr) ? YES : NO;
    }
    
#else
    
    NSData* encryptDataRSA(NSData* rawData, SecKeyRef publicKey, CFStringRef paddingStr)
    {
        NSData *cipherData = nil;
        
        BOOL                success = YES;
        CFErrorRef          errorCF = NULL;
        SecTransformRef     transform = NULL;
        CFDataRef           resultData = NULL;
        
        // Now create and execute the transform.
        if (success)
        {
            transform = SecEncryptTransformCreate(publicKey, &errorCF);
            
            success = (transform != NULL);
        }
        if (success && (paddingStr != NULL))
        {
            success = SecTransformSetAttribute(transform, kSecPaddingKey, paddingStr, &errorCF) != false;
        }
        if (success)
        {
            success = SecTransformSetAttribute(transform, kSecTransformInputAttributeName, (__bridge CFDataRef)rawData, &errorCF) != false;
        }
        if (success)
        {
            resultData = (CFDataRef)SecTransformExecute(transform, &errorCF);
            success = (resultData != NULL);
        }
        if (success)
        {
            cipherData = [[(__bridge NSData *) resultData retain] autorelease];
        }
        else
        {
            assert(errorCF != NULL);
        }
        
        // Clean up
        if (resultData != NULL)
        {
            CFRelease(resultData);
        }
        
        if (errorCF != NULL) {
            CFRelease(errorCF);
        }
        if (transform != NULL)
        {
            CFRelease(transform);
        }
        
        return cipherData;
    }
    
    NSData* decryptDataRSA(NSData* encryptedData, SecKeyRef privateKey, CFStringRef paddingStr)
    {
        NSData *plainData = nil;
        
        BOOL                success = YES;
        CFErrorRef          errorCF = NULL;
        SecTransformRef     transform = NULL;
        CFDataRef           resultData = NULL;
        
        // Now create and execute the transform.
        if (success)
        {
            transform = SecDecryptTransformCreate(privateKey, &errorCF);
            success = (transform != NULL);
        }
        if (success && (paddingStr != NULL))
        {
            success = SecTransformSetAttribute(transform, kSecPaddingKey, paddingStr, &errorCF) != false;
        }
        if (success)
        {
            success = SecTransformSetAttribute(transform, kSecTransformInputAttributeName, (__bridge CFDataRef)encryptedData, &errorCF) != false;
        }
        if (success)
        {
            resultData = (CFDataRef)SecTransformExecute(transform, &errorCF);
            success = (resultData != NULL);
        }
        if (success)
        {
            plainData = [[(__bridge NSData *) resultData retain] autorelease];;
        }
        else
        {
            assert(errorCF != NULL);
        }
        
        // Clean up
        if (resultData != NULL)
        {
            CFRelease(resultData);
        }
        if (errorCF != NULL)
        {
            CFRelease(errorCF);
        }
        if (transform != NULL)
        {
            CFRelease(transform);
        }
        
        return plainData;
    }
    
    NSData* getSignatureBytes(NSData *plainData, SecKeyRef privateKey, CFStringRef paddingStr)
    {
        if (plainData == nil || privateKey == nil || paddingStr == nil)
        {
            return nil;
        }
        
        NSData *signatureData = nil;
        BOOL                success = NO;
        SecTransformRef     transform = NULL;
        CFDataRef           resultData = NULL;
        CFErrorRef          errorCF = NULL;
        
        // Set up the transform.
        transform = SecSignTransformCreate(privateKey, &errorCF);
        success = (transform != NULL);
        
        if (success)
        {
            success = SecTransformSetAttribute(transform, kSecDigestTypeAttribute, paddingStr, &errorCF) != false;
        }
        
        if (success)
        {
            success = SecTransformSetAttribute(transform, kSecTransformInputAttributeName, (__bridge CFDataRef)plainData, &errorCF) != false;
        }
        
        // Run it.
        if (success)
        {
            resultData = (CFDataRef)SecTransformExecute(transform, &errorCF);
            success = (resultData != NULL);
        }
        
        // Process the results.
        if (success)
        {
            assert(CFGetTypeID(resultData) == CFDataGetTypeID());
            signatureData = [[(__bridge NSData *) resultData retain] autorelease];
        }
        else
        {
            assert(errorCF != NULL);
        }
        
        // Clean up.
        if (resultData != NULL)
        {
            CFRelease(resultData);
        }
        if (errorCF != NULL)
        {
            CFRelease(errorCF);
        }
        if (transform != NULL)
        {
            CFRelease(transform);
        }
        
        return signatureData;
    }
    
    BOOL verifySignature(NSData* plainData, SecKeyRef publicKey, CFStringRef paddingStr, NSData* signature)
    {
        if (plainData == nil || publicKey == nil || signature == nil || paddingStr == nil)
        {
            return NO;
        }
        
        BOOL verified = NO;
        BOOL                success = NO;
        SecTransformRef     transform = NULL;
        CFBooleanRef        result = NULL;
        CFErrorRef          errorCF = NULL;
        
        // Set up the transform.
        transform = SecVerifyTransformCreate(publicKey, (__bridge CFDataRef)signature, &errorCF);
        success = (transform != NULL);
        
        // Note: kSecInputIsAttributeName defaults to kSecInputIsPlainText, which is what we want.
        if (success)
        {
            success = SecTransformSetAttribute(transform, kSecDigestTypeAttribute, paddingStr, &errorCF) != false;
        }
        
        if (success)
        {
            success = SecTransformSetAttribute(transform, kSecTransformInputAttributeName, (__bridge CFDataRef)plainData, &errorCF) != false;
        }
        
        // Run it.
        if (success)
        {
            result = (CFBooleanRef)SecTransformExecute(transform, &errorCF);
            success = (result != NULL);
        }
        
        // Process the results.
        if (success)
        {
            assert(CFGetTypeID(result) == CFBooleanGetTypeID());
            verified = (CFBooleanGetValue(result) != false);
        }
        else
        {
            assert(errorCF != NULL);
        }
        
        // Clean up.
        if (result != NULL)
        {
            CFRelease(result);
        }
        if (errorCF != NULL)
        {
            CFRelease(errorCF);
        }
        if (transform != NULL)
        {
            CFRelease(transform);
        }
        
        return verified;
    }
    
#endif
    
#ifdef __cplusplus
}
#endif

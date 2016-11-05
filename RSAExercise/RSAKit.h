//
//  RSAKit.h
//  RSAExercise
//
//  Created by _ivanC on 04/02/15.
//  Copyright © 2015 _ivanC. All rights reserved.
//

#ifndef RSAKit_h
#define RSAKit_h

#import <Foundation/Foundation.h>
#import <Security/Security.h>

#ifdef __cplusplus
extern "C"{
#endif
    
    SecKeyRef createPublicKeyRef(NSString* certPath);
    SecKeyRef createPrivateKeyRef(NSString* certPath, NSString *password);
    
#if (TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR)
    NSData* encryptDataRSA(NSData* rawData, SecKeyRef publicKey, SecPadding padding);
    NSData* decryptDataRSA(NSData* encryptedData, SecKeyRef privateKey, SecPadding padding);
    
    NSData* getSignatureBytes(NSData *plainData, SecKeyRef privateKey, SecPadding padding);
    BOOL verifySignature(NSData* plainData, SecKeyRef publicKey, SecPadding padding, NSData* signature);
#else
    
    // For an RSA key the transform does PKCS#1 padding by default.  Weirdly, if we explicitly
    // set the padding to kSecPaddingPKCS1Key then the transform fails <rdar://problem/13661366>.
    // Thus, if the client has requested PKCS#1, we leave paddingStr set to NULL, which prevents
    // us explicitly setting the padding to anything, which avoids the error while giving us
    // PKCS#1 padding.
    
    NSData* encryptDataRSA(NSData* rawData, SecKeyRef publicKey, CFStringRef paddingStr);
    NSData* decryptDataRSA(NSData* encryptedData, SecKeyRef privateKey, CFStringRef paddingStr);
    
    NSData* getSignatureBytes(NSData *plainData, SecKeyRef privateKey, CFStringRef paddingStr);
    BOOL verifySignature(NSData* plainData, SecKeyRef publicKey, CFStringRef paddingStr, NSData* signature);
#endif
    
#ifdef __cplusplus
}
#endif

#endif  /* RSAKit_h */

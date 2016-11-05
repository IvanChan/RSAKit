//
//  ViewController.m
//  RSAExercise
//
//  Created by _ivanC on 05/11/2016.
//  Copyright © 2016 _ivanC. All rights reserved.
//

#import "ViewController.h"
#import "RSAKit.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
}


- (BOOL)verifyData:(NSData *)targetData withCodesign:(NSString *)codesignString
{
    BOOL codesignVerified = NO;
    do {
        
        // Verify Codesign
        NSString *certPath = [[NSBundle mainBundle] pathForResource:@"publickey" ofType:@"der"];
        SecKeyRef publicKey = createPublicKeyRef(certPath);
        
        if (!publicKey)
        {
            break;
        }
        
        NSData *codesignData = [[NSData alloc] initWithBase64EncodedString:codesignString
                                                                   options:NSDataBase64DecodingIgnoreUnknownCharacters];
        
        NSString *rawString = nil; // FIXME:
        NSData *rawData = [rawString dataUsingEncoding:NSUTF8StringEncoding];
        
        NSData *sha1Data = rawData; // FIXME: [rawData SHA1]
        codesignVerified = verifySignature(sha1Data, publicKey, kSecPaddingPKCS1SHA1, codesignData);
        
        CFRelease(publicKey);
        publicKey = NULL;

    } while (0);
    
    return codesignVerified;
}


@end

//
//  File.swift
//  
//
//  Created by Igor Dvoeglazov on 15.06.2022.
//

import Foundation
import UIKit

extension X509 {
    /// Certificate Revocation List
    public struct CRL {
        public var signatureAlgorithm: AlgorithmIdentifier
        public var signatureValue: BitString
        public var tbsCertList: TBSCertList
        
        var data: [UInt8]
        
        init?(derData : [UInt8])
        {
            guard let certificate = ASN1Parser(data: derData).parseObject() as? ASN1Sequence else { return nil }
            self.init(asn1sequence: certificate)
            self.data = derData
        }
        
        public init?(derData : Data) {
            self.init(derData: derData.UInt8Array())
        }
        
        init?(asn1sequence: ASN1Sequence) {
            guard asn1sequence.objects.count == 3 else { return nil }
            
            guard let asn1TBSCertList           = asn1sequence.objects[0] as? ASN1Sequence else { return nil }
            guard let asn1signatureAlgorithm    = asn1sequence.objects[1] as? ASN1Sequence  else { return nil }
            guard let asn1signature             = asn1sequence.objects[2] as? ASN1BitString else { return nil }
            
            guard let signatureAlgorithm = AlgorithmIdentifier(asn1sequence: asn1signatureAlgorithm) else { return nil }
            guard let signature = BitString(bitString: asn1signature) else { return nil }
            
            guard let certList = TBSCertList(asn1Sequence: asn1TBSCertList) else { return nil }
            self.tbsCertList = certList
            
            self.signatureAlgorithm = signatureAlgorithm
            self.signatureValue = signature
            
            self.data = []
        }
        
        public struct TBSCertList {
            public var version: CertificateVersion?
            public var signature: AlgorithmIdentifier
            public var issuer: Name
            public var thisUpdate: Time
            public var nextUpdate: Time?
            
            /* When there are no revoked certificates, the revoked certificates list MUST be absent. */
            public var revokedCertificates: [RevokedCertificate]?
            
            init?(asn1Sequence sequence: ASN1Sequence)
            {
                var offset = 0
                if let asn1tbsCertVersion = sequence.objects[0] as? ASN1Integer {
                    if let version = CertificateVersion(rawValue:Int(asn1tbsCertVersion.value[0])),
                       version == .v2 {
                        self.version = version
                    } else {
                        return nil
                    }
                    offset = 1
                }
                guard let asn1signatureAlgorithm2   = sequence.objects[offset] as? ASN1Sequence  else { return nil }
                guard let asn1issuer                = sequence.objects[offset + 1] as? ASN1Sequence  else { return nil }
                guard let asn1thisUpdate            = sequence.objects[offset + 2] as? ASN1Time      else { return nil }
                if let asn1nextUpdate  = sequence.objects[offset + 3] as? ASN1Time {
                    self.nextUpdate = Time(time: asn1nextUpdate)
                    offset += 1
                }
                if let asn1revokedCertificates = sequence.objects[offset + 3] as? ASN1Sequence {
                    self.revokedCertificates = asn1revokedCertificates.objects
                        .compactMap({ $0 as? ASN1Sequence })
                        .compactMap({ RevokedCertificate.init(asn1sequence: $0) })
                }
                
                guard let signature = AlgorithmIdentifier(asn1sequence: asn1signatureAlgorithm2) else { return nil }
                self.signature = signature
                
                guard let issuer = Name(asn1sequence: asn1issuer) else { return nil }
                self.issuer = issuer
                
                guard let thisUpdate = Time(time: asn1thisUpdate) else { return nil }
                self.thisUpdate = thisUpdate
            }
        }
        
        public struct RevokedCertificate {
            public var userCertificate: BigInt
            public var revocationDate: Time
            
            init?(asn1sequence: ASN1Sequence)
            {
                guard let asn1userCertificate   = asn1sequence.objects[0] as? ASN1Integer,
                      let asn1revocationDate    = asn1sequence.objects[1] as? ASN1Time,
                      let revocationDate        = Time(time: asn1revocationDate)
                else { return nil }
                
                self.userCertificate = BigInt(bigEndianParts: asn1userCertificate.value)
                self.revocationDate = revocationDate
            }
            
            public var description: String {
                switch revocationDate {
                case .utcTime(let string):
                    return string + ": \(userCertificate)"
                case .generalizedTime(let string):
                    return string + ": \(userCertificate)"
                }                
            }
        }
        
    }
}

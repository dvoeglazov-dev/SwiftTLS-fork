import Foundation
import PlaygroundSupport
import CommonCrypto
import SwiftTLS

extension String {
    var fileData: Data? {
        let components = components(separatedBy: ".")
        var ext: String?
        if components.count > 1 {
            ext = components.last!
        }
        let resource = components.dropLast().joined(separator: ".")
        guard let fileUrl = Bundle.main.url(forResource: resource,
                                            withExtension: ext)
        else { return nil }
        
        do {
            let data = try Data(contentsOf: fileUrl)
            print("Cert: " + resource + "." + (ext ?? ""))
            return data
        } catch {
            print(error)
        }
        return nil
    }
}

func sha256(data : Data) -> Data {
    var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
    data.withUnsafeBytes {
        _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
    }
    return Data(hash)
}

public class Verifier {

    public private(set) var pinnedCertSHA256: Data?
    
    private let caCertData: Data
    private var crlData: Data?
    
    private let caCert: X509.Certificate
    private var crl: X509.CRL? // class CRL
    
    public init?(caCertData data: Data, crlData: Data) {
        guard let caCert = X509.Certificate(derData: data), // struct Certificate
              let signer = caCert.publicKeySigner // struct RSA
        else { return nil }
        self.caCert = caCert
        self.caCertData = data
        
        if let crl = X509.CRL(derData: crlData),
           let crlTbs = crl.tbsCertList.DEREncodedCertificate {
            // Check crl signature
            do {
                if try signer.verify(signature: crl.signatureValue.bits,
                                     data: crlTbs) {
                    self.crl = crl
                    self.crlData = crlData
                    print("CRL signature verified")
                }
            } catch {
                print(error)
            }
        }
    }
    
    deinit {
        print("Verifier deinit")
    }
    
    public enum CertificateVerifyState {
        case wrongFormat
        case pinned
        case wrongSign(error: Error?)
        case signed(serial: String)
        case revoked(date: String)
        case verified
    }
    
    func pinCert(data: Data) {
        let certHash = sha256(data: data)
        pinnedCertSHA256 = certHash
    }
    
    func verifyCertificate(data: Data) -> CertificateVerifyState {
        // 1. Check pinning
        if let pinned = pinnedCertSHA256 {
            let certHash = sha256(data: data)
            if certHash == pinned {
                return .pinned
            }
        }
        
        guard let cert = X509.Certificate(derData: data)
        else { return .wrongFormat }
    
        // 2. Check certificate signature
        let state = verifySignature(cert: cert)
        
        guard case .signed(let serialNumber) = state,
              let tbsCertList = crl?.tbsCertList
        else { return state }
        
        // 3. Check wether certificate in Certificate Revocation list
        if tbsCertList.revokedCertificates != nil {
            if let revokedCertRecord = tbsCertList.revokedCertificates!.first(where: { $0.userCertificate == serialNumber }) {
                return .revoked(date: revokedCertRecord.revocationDate)
            }
        }
        return .verified
    }

    private func verifySignature(cert: X509.Certificate) -> CertificateVerifyState {
        
        let serial = String(cert.tbsCertificate.serialNumber)
        
        guard let signer = caCert.publicKeySigner,
              let tbs = cert.tbsCertificate.DEREncodedCertificate
        else { return .wrongFormat }
        
        do {
            if try signer.verify(signature: cert.signatureValue.bits,
                                 data: tbs) {
                return .signed(serial: serial)
            } else {
                return .wrongSign(error: nil)
            }
        } catch {
            return .wrongSign(error: error)
        }
    }
}

if let caData = "CA Promsvyazbank PJSC.cer".fileData, // "Russian Trusted Sub CA.cer".fileData,
   let crlData = "psbankws.crl".fileData,
   let verifier = Verifier(caCertData: caData, crlData: crlData) {
    
    if let certData = "retail-tst.payment.ru.cer".fileData {
        
//        verifier.pinCert(data: certData)
        
        let certState = verifier.verifyCertificate(data: certData)
        print(certState)
        
    } else {
        print("Can't create cert")
    }
} else {
    print("Can't create Verifier object")
}

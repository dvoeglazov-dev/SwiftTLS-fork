import Foundation
import PlaygroundSupport
import CommonCrypto
import SwiftTLS

func certFileData(name: String) -> Data? {
    let components = name.components(separatedBy: ".")
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

func verify(certName: String, caName: String) throws -> (Bool, String) {
    
    guard let data = certFileData(name: certName),
          let cert = X509.Certificate(derData: data)
    else { return (false, "") }
    
    let serial = String(cert.tbsCertificate.serialNumber)
    
    guard let tbs = cert.tbsCertificate.DEREncodedCertificate,
          let caData = certFileData(name: caName), //"Russian Trusted Sub CA.cer"),
          let caCert = X509.Certificate(derData: caData),
          let signer = caCert.publicKeySigner
    else { return (false, serial) }
    
    do {
        let isVerified = try signer.verify(signature: cert.signatureValue.bits,
                                     data: tbs)
        return (isVerified, serial)
    }
}

func checkCRL(serial: String) -> Bool {
    guard let data = certFileData(name: "psbankws.crl")
    else {return false }
    
    guard let crl = X509.CRL(derData: data)
    else { return false }
    
    if let list = crl.tbsCertList.revokedCertificates {
        list.forEach({ print($0.description) })
        let crl = list.map({ String($0.userCertificate) })
        
        return crl.contains(serial)
    }
    return true
}

do {
    let tuple = try verify(certName: "retail-tst.payment.ru.4443.cer", caName: "Russian Trusted Sub CA.cer")
    
    let serial = tuple.1
    
    if tuple.0 {
        print("Valid! Serial: \(serial)")
        if checkCRL(serial: serial) {
            print("Cert REVOKED!")
        } else {
            print("Cert OK, not revoked!")
        }
    } else {
        print("Bad cert! Serial: \(serial)")
    }
    
} catch {
    print(error)
}


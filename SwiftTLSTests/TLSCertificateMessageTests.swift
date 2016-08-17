//
//  TLSCertificateMessageTests.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 27.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Cocoa
import XCTest
@testable import SwiftTLS

class TLSCertificateMessageTests: XCTestCase {

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func test_writeTo_withOneCertificate_givesDataFromWhichTheSameMessageCanBeConstructed()
    {
        let certificateURL = Bundle(for: type(of: self)).url(forResource: "certificate", withExtension: "cer")!
        let certificateData = try! Data(contentsOf: certificateURL)
        let certificate = X509.Certificate(derData: certificateData)!
        let sut = TLSCertificateMessage(certificates: [certificate])

        var data = DataBuffer()
        sut.writeTo(&data)
        let cert2Message = TLSCertificateMessage(inputStream: BinaryInputStream(data.buffer), context: TLSContext())!
        var data2 = DataBuffer()
        cert2Message.writeTo(&data2)
        
        XCTAssertEqual(data.buffer, data2.buffer)
    }
}

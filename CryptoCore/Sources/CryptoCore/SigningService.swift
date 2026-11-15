import Foundation
import CryptoKit

public struct SigningService {
    public static func sign(message: Data, privateKey: Curve25519.Signing.PrivateKey) throws -> Data {
        return try privateKey.signature(for: message)
    }

    public static func verify(signature: Data, message: Data, publicKey: Curve25519.Signing.PublicKey) -> Bool {
        guard signature.count == 64 else { return false }
        return publicKey.isValidSignature(signature, for: message)
    }

    public static func sign(
        text: String,
        privateKey: Curve25519.Signing.PrivateKey
    ) throws -> String {
        let sig = try sign(message: Data(text.utf8), privateKey: privateKey)
        return sig.base64EncodedString()
    }

    public static func verify(
        base64Signature: String,
        text: String,
        base64PublicKey: String
    ) -> Bool {
        guard let sigData = Data(base64Encoded: base64Signature),
              let pubData = Data(base64Encoded: base64PublicKey),
              pubData.count == 32 else {
            return false
        }

        guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: pubData) else {
            return false
        }

        return verify(signature: sigData, message: Data(text.utf8), publicKey: publicKey)
    }
}

// PdfRemoteSignDocumentSession.cpp

#ifdef _MSC_VER
#  define _CRT_SECURE_NO_WARNINGS
#endif

#include <podofo/private/OpenSSLInternal.h>
#include <openssl/bio.h>
#include "PdfRemoteSignDocumentSession.h"
#include <iterator>  // for std::istreambuf_iterator

using namespace std;
using namespace PoDoFo;
namespace fs = std::filesystem;

// free‐function moved here
static std::vector<unsigned char> ReadBinary(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return { std::istreambuf_iterator<char>(f),
             std::istreambuf_iterator<char>() };
}

// BioFreeAll implementation
void BioFreeAll::operator()(BIO* b) const noexcept {
    if (b) BIO_free_all(b);
}

// Constructor
PdfRemoteSignDocumentSession::PdfRemoteSignDocumentSession(
    const std::string& conformanceLevel,
    const std::string& hashAlgorithmOid,
    const std::string& documentInputPath,
    const std::string& documentOutputPath,
    const std::string& endCertificateBase64,
    const std::vector<std::string>& certificateChainBase64,
    const std::optional<std::string>& rootEntityCertificateBase64
)
    : _conformanceLevel(conformanceLevel)
    , _hashAlgorithm(hashAlgorithmFromOid(hashAlgorithmOid))
    , _documentInputPath(documentInputPath)
    , _documentOutputPath(documentOutputPath)
    , _endCertificateBase64(endCertificateBase64)
    , _certificateChainBase64(certificateChainBase64)
    , _rootCertificateBase64(rootEntityCertificateBase64)
{
    // Convert the certificates during construction
    _endCertificateDer = ConvertBase64PEMtoDER(endCertificateBase64, "input/endCertificate.der");

    // Convert each certificate in the chain
    _certificateChainDer.reserve(certificateChainBase64.size());
    for (size_t i = 0; i < certificateChainBase64.size(); ++i) {
        std::string outputPath = "input/chainCertificate" + std::to_string(i) + ".der";
        _certificateChainDer.push_back(ConvertBase64PEMtoDER(certificateChainBase64[i], outputPath));
    }

    // Convert root certificate if provided
    if (_rootCertificateBase64) {
        _rootCertificateDer = ConvertBase64PEMtoDER(*_rootCertificateBase64, "input/rootCertificate.der");
    }
}

// Destructor
PdfRemoteSignDocumentSession::~PdfRemoteSignDocumentSession() = default;

// beginSigning()
std::string PdfRemoteSignDocumentSession::beginSigning() {
    try {
        cout << "\n=== Starting PDF Signing Process ===" << endl;
        fs::copy_file(_documentInputPath, _documentOutputPath, fs::copy_options::overwrite_existing);
        _stream = make_shared<FileStreamDevice>(_documentOutputPath, FileMode::Open);

        string cert;
        cert.assign(_endCertificateDer.begin(), _endCertificateDer.end());
        cout << "Certificate size: " << cert.size() << " bytes" << endl;

        _doc.Load(_stream);

        auto& acroForm = _doc.GetOrCreateAcroForm();
        acroForm.GetDictionary().AddKey("SigFlags"_n, (int64_t)3);

        auto& page = _doc.GetPages().GetPageAt(0);
        auto& field = page.CreateField("Signature", PdfFieldType::Signature, Rect(0, 0, 0, 0));
        auto& signature = static_cast<PdfSignature&>(field);
        signature.MustGetWidget().SetFlags(PdfAnnotationFlags::Invisible | PdfAnnotationFlags::Hidden);
        signature.SetSignatureReason(PdfString("Document approval"));
        signature.SetSignerName(PdfString("Custom User"));
        //signature.SetSignatureDate(PoDoFo::PdfDate::ParseW3C("2025-04-01T00:00:0.000000Z"));
        signature.SetSignatureDate(PdfDate::LocalNow());

        cout << "Setting up signing parameters..." << endl;
        if (_conformanceLevel == "Ades_B_B") {
            _cmsParams.SignatureType = PdfSignatureType::PAdES_B;
        }
        else if (_conformanceLevel == "Ades_B_T") {
            throw runtime_error("Conformance level Ades_B_T is not supported yet");
        }
        else if (_conformanceLevel == "Ades_B_LT") {
            throw runtime_error("Conformance level Ades_B_LT is not supported yet");
        }
        else if (_conformanceLevel == "Ades_B_LTA") {
            throw runtime_error("Conformance level Ades_B_LTA is not supported yet");
        }
        else {
            throw runtime_error("Invalid conformance level");
        }

        if (_hashAlgorithm == HashAlgorithm::SHA256) {
            _cmsParams.Hashing = PdfHashingAlgorithm::SHA256;
        }
        else if (_hashAlgorithm == HashAlgorithm::SHA384) {
            _cmsParams.Hashing = PdfHashingAlgorithm::SHA384;
        }
        else if (_hashAlgorithm == HashAlgorithm::SHA512) {
            _cmsParams.Hashing = PdfHashingAlgorithm::SHA512;
        }
        else {
            throw runtime_error("Hash algorithm is not supported");
        }

        auto signer = make_shared<PdfSignerCms>(cert, _cmsParams);
        _signerId = _ctx.AddSigner(signature, signer);

        cout << "Starting signing process..." << endl;
        _ctx.StartSigning(_doc, _stream, _results, PdfSaveOptions::NoMetadataUpdate);

        auto& INITIAL_hash = _results.Intermediate[_signerId];
        auto rawCmsHash = ToHexString(INITIAL_hash);
        cout << "Hash (hex): " << rawCmsHash << endl;

        auto binaryHash = HexToBytes(rawCmsHash);
        charbuff binaryCharbuff;
        binaryCharbuff.assign(reinterpret_cast<const char*>(binaryHash.data()), binaryHash.size());

        auto base64Hash = ToBase64(binaryCharbuff);
        cout << "Hash (base64): " << base64Hash << endl;

        auto urlEncodedHash = UrlEncode(base64Hash);
        cout << "Hash (URL-encoded): " << urlEncodedHash << endl;
        cout << "=== Signing Process Started Successfully ===\n" << endl;

        return urlEncodedHash;
    }
    catch (const exception& e) {
        cout << "\n=== Error in Signing Process ===" << endl;
        cout << "Error: " << e.what() << endl;
        _stream.reset();
        throw;
    }
}

// finishSigning()
void PdfRemoteSignDocumentSession::finishSigning(const string& signedHash) {
    try {
        cout << "\n=== Finishing Signing Process ===" << endl;
        auto buff = ConvertDSSHashToSignedHash(signedHash);
        _results.Intermediate[_signerId] = buff;
        _ctx.FinishSigning(_results);
        cout << "=== Signing Process Completed Successfully ===\n" << endl;
    }
    catch (const exception& e) {
        cout << "\n=== Error in Finish Signing ===" << endl;
        cout << "Error: " << e.what() << endl;
        _stream.reset();
        throw;
    }
}

// ConvertBase64PEMtoDER()
std::vector<unsigned char> PdfRemoteSignDocumentSession::ConvertBase64PEMtoDER(
    const optional<string>& base64PEM,
    const optional<string>& outputPath)
{
    if (!base64PEM || base64PEM->empty())
        return {};

    BIO* raw_b64 = BIO_new(BIO_f_base64());
    if (!raw_b64) throw runtime_error("Failed to create BIO for Base64");
    BIO_set_flags(raw_b64, BIO_FLAGS_BASE64_NO_NL);

    BIO* raw_mem = BIO_new_mem_buf(base64PEM->data(), static_cast<int>(base64PEM->size()));
    if (!raw_mem) {
        BIO_free_all(raw_b64);
        throw runtime_error("Failed to create memory BIO");
    }

    BIO* raw_chain = BIO_push(raw_b64, raw_mem);
    BioPtr bio(raw_chain);

    vector<unsigned char> der((base64PEM->size() * 3) / 4);
    int len = BIO_read(bio.get(), der.data(), static_cast<int>(der.size()));
    if (len <= 0) throw runtime_error("Base64 decode failed");
    der.resize(len);

    //if (outputPath && !outputPath->empty()) {
    //    ofstream out(*outputPath, ios::binary);
    //    if (!out) throw runtime_error("Failed to open output file for DER writing");
    //    out.write(reinterpret_cast<const char*>(der.data()), static_cast<streamsize>(der.size()));
    //}
    return der;
}

// ReadFile()
void PdfRemoteSignDocumentSession::ReadFile(const string& filepath, string& str) {
    ifstream file(filepath, ios::binary);
    if (file) {
        str.assign((istreambuf_iterator<char>(file)), {});
    }
    else {
        throw runtime_error("Cannot open file: " + filepath);
    }
}

// ToBase64()
string PdfRemoteSignDocumentSession::ToBase64(const charbuff& data) {
    BIO* raw_b64 = BIO_new(BIO_f_base64()); BIO_set_flags(raw_b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* raw_mem = BIO_new(BIO_s_mem());
    BIO* raw_chain = BIO_push(raw_b64, raw_mem);
    BioPtr bio(raw_chain);

    if (BIO_write(bio.get(), data.data(), static_cast<int>(data.size())) <= 0 ||
        BIO_flush(bio.get()) <= 0)
        throw runtime_error("BIO_write/flush failed");

    BUF_MEM* ptr;
    BIO_get_mem_ptr(bio.get(), &ptr);
    return string(ptr->data, ptr->length);
}

// ConvertDSSHashToSignedHash()
charbuff PdfRemoteSignDocumentSession::ConvertDSSHashToSignedHash(const string& DSSHash) {
    BIO* raw_b64 = BIO_new(BIO_f_base64()); BIO_set_flags(raw_b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* raw_mem = BIO_new_mem_buf(DSSHash.data(), static_cast<int>(DSSHash.size()));
    BIO* raw_chain = BIO_push(raw_b64, raw_mem);
    BioPtr bio(raw_chain);

    vector<unsigned char> decoded(128);
    int len = BIO_read(bio.get(), decoded.data(), static_cast<int>(decoded.size()));
    if (len <= 0) throw runtime_error("Base64 decode failed");
    decoded.resize(len);

    charbuff result;
    result.assign(decoded.begin(), decoded.end());
    return result;
}

// HexToBytes()
vector<unsigned char> PdfRemoteSignDocumentSession::HexToBytes(const string& hex) {
    vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// ToHexString()
string PdfRemoteSignDocumentSession::ToHexString(const charbuff& data) {
    stringstream ss;
    ss << hex << setfill('0');
    for (unsigned char c : data) {
        ss << setw(2) << static_cast<int>(c);
    }
    return ss.str();
}

// UrlEncode()
string PdfRemoteSignDocumentSession::UrlEncode(const string& value) {
    ostringstream escaped; escaped.fill('0'); escaped << hex;
    for (unsigned char c : value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        }
        else {
            escaped << '%' << setw(2) << uppercase << static_cast<int>(c);
        }
    }
    return escaped.str();
}

// printState()
void PdfRemoteSignDocumentSession::printState() const {
    cout << "PdfSigningSession state:\n";
    cout << "  ConformanceLevel: " << _conformanceLevel << "\n";
    cout << "  HashAlgorithm:    " << hashAlgorithmToString(_hashAlgorithm) << "\n";
    cout << "  DocumentInput:    " << _documentInputPath << "\n";
    cout << "  DocumentOutput:   " << _documentOutputPath << "\n";
    cout << "  EndCert (bytes):  " << _endCertificateBase64.size() << "\n";
    cout << "  ChainCount:       " << _certificateChainBase64.size() << "\n";
    if (_rootCertificateBase64)
        cout << "  RootCert (bytes): " << _rootCertificateBase64->size() << "\n";
}

// static helpers
HashAlgorithm PdfRemoteSignDocumentSession::hashAlgorithmFromOid(const string& oid) {
    if (oid == "2.16.840.1.101.3.4.2.1") return HashAlgorithm::SHA256;
    if (oid == "2.16.840.1.101.3.4.2.2") return HashAlgorithm::SHA384;
    if (oid == "2.16.840.1.101.3.4.2.3") return HashAlgorithm::SHA512;
    return HashAlgorithm::Unknown;
}

const char* PdfRemoteSignDocumentSession::hashAlgorithmToString(HashAlgorithm alg) {
    switch (alg) {
    case HashAlgorithm::SHA256: return "SHA-256";
    case HashAlgorithm::SHA384: return "SHA-384";
    case HashAlgorithm::SHA512: return "SHA-512";
    default:                    return "Unknown";
    }
}

// PdfDssSigningSession.h
#ifndef PDF_DSS_SIGNING_SESSION_H
#define PDF_DSS_SIGNING_SESSION_H

#ifdef _MSC_VER
#  define _CRT_SECURE_NO_WARNINGS
#endif

#include <iostream>
#include <fstream>
#include <limits>
#include <iomanip>
#include <sstream>
#include <vector>
#include <memory>
#include <optional>
#include <string>
#include <regex>
#include <thread>
#include <filesystem>

#include <podofo/podofo.h>
#include <podofo/private/OpenSSLInternal.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

using namespace std;
using namespace PoDoFo;
namespace fs = std::filesystem;

namespace PoDoFo {

// RAII wrapper for OpenSSL BIO*
struct PODOFO_API BioFreeAll {
    void operator()(BIO* b) const noexcept;
};
using BioPtr = std::unique_ptr<BIO, BioFreeAll>;

enum class ConformanceLevel {
    Ades_B_B,
    Ades_B_T,
    Ades_B_LT,
    Ades_B_LTA
};

enum class HashAlgorithm {
    SHA256,
    SHA384,
    SHA512,
    Unknown
};

// your document entry:
struct DocumentConfig {
    std::string                document_input_path;
    std::string                document_output_path;
    ConformanceLevel           conformance_level;
};

// top‐level request:
struct SigningRequest {
    std::vector<DocumentConfig>              documents;
    std::vector<unsigned char>               endEntityCertificate;
    std::vector<std::vector<unsigned char>>  certificateChain;
    std::string                              hashAlgorithmOID;
};

// utility to read a file fully into a vector<byte>
static std::vector<unsigned char> ReadBinary(const std::string& path);

// Represents a PDF signing session
class PODOFO_API PdfDssSigningSession final {
public:
    // Construct a signing session with full configuration
    PdfDssSigningSession(
        ConformanceLevel conformanceLevel,
        const std::string& hashAlgorithmOid,
        const std::string& documentInputPath,
        const std::string& documentOutputPath,
        const std::string& endCertificateBase64,
        const std::vector<std::string>& certificateChainBase64,
        const std::optional<std::string>& rootEntityCertificateBase64 = std::nullopt
    );

    PdfDssSigningSession(const PdfDssSigningSession&) = delete;
    PdfDssSigningSession& operator=(const PdfDssSigningSession&) = delete;
    PdfDssSigningSession(PdfDssSigningSession&&) noexcept = default;
    PdfDssSigningSession& operator=(PdfDssSigningSession&&) noexcept = default;
    ~PdfDssSigningSession();

    std::string beginSigning();
    void finishSigning(const std::string& signedHash);
    void printState() const;

private:
    std::vector<unsigned char> ConvertBase64PEMtoDER(
        const std::optional<std::string>& base64PEM,
        const std::optional<std::string>& outputPath);
    void ReadFile(const std::string& filepath, std::string& str);
    std::string ToBase64(const charbuff& data);
    charbuff ConvertDSSHashToSignedHash(const std::string& DSSHash);
    std::vector<unsigned char> HexToBytes(const std::string& hex);
    std::string ToHexString(const charbuff& data);
    std::string UrlEncode(const std::string& value);

    ConformanceLevel                            _conformanceLevel;
    HashAlgorithm                               _hashAlgorithm;
    std::string                                 _documentInputPath;
    std::string                                 _documentOutputPath;
    std::string                                 _endCertificateBase64;
    std::vector<std::string>                    _certificateChainBase64;
    std::optional<std::string>                  _rootCertificateBase64;
    std::vector<unsigned char>                  _endCertificateDer;
    std::vector<std::vector<unsigned char>>     _certificateChainDer;
    std::vector<unsigned char>                  _rootCertificateDer;

    PdfMemDocument                              _doc;
    std::shared_ptr<FileStreamDevice>           _stream;
    PdfSignerCmsParams                          _cmsParams;
    PdfSigningContext                           _ctx;
    PdfSigningResults                           _results;
    PdfSignerId                                 _signerId;

    static HashAlgorithm hashAlgorithmFromOid(const std::string& oid);
    static const char* hashAlgorithmToString(HashAlgorithm alg);
    static const char* conformanceLevelToString(ConformanceLevel level);
};

} // namespace PoDoFo

#endif // PDF_DSS_SIGNING_SESSION_H
